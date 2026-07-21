package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/instantmesh/instantmesh/pkg/auditlog"
)

// Sink は監査バッチ（NDJSON バイト列）を宛先へ書き出す抽象。実体は S3Sink（本番）で、テストは
// フェイクを差し込む。純粋なシリアライズ／バッチ判断は pkg/auditlog にあり、本抽象は I/O のみ。
type Sink interface {
	Put(ctx context.Context, key string, body []byte) error
}

// S3Sink は監査ログを S3 へ PutObject する Sink。Object Lock（WORM）と保持期間はバケット側の
// デフォルト設定＋ライフサイクルに委ね、KMS キーが指定されていれば SSE-KMS で暗号化する。
type S3Sink struct {
	client   *s3.Client
	bucket   string
	kmsKeyID string // 空ならバケット既定の暗号化に委ねる
}

// NewS3Sink は既定の認証チェーン（EC2 インスタンスロール等）で S3 クライアントを構築する。
func NewS3Sink(ctx context.Context, region, bucket, kmsKeyID string) (*S3Sink, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws config: %w", err)
	}
	return &S3Sink{client: s3.NewFromConfig(cfg), bucket: bucket, kmsKeyID: kmsKeyID}, nil
}

// Put は Sink を実装する。
func (s *S3Sink) Put(ctx context.Context, key string, body []byte) error {
	in := &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/x-ndjson"),
	}
	if s.kmsKeyID != "" {
		in.ServerSideEncryption = s3types.ServerSideEncryptionAwsKms
		in.SSEKMSKeyId = aws.String(s.kmsKeyID)
	}
	_, err := s.client.PutObject(ctx, in)
	return err
}

// putTimeout は 1 バッチの書き込みタイムアウト。
const putTimeout = 30 * time.Second

// BufferedAuditLogger は監査イベントをバッファし、件数（maxBatch）または経過時間（maxAge）で
// バッチにまとめて Sink へ書き出す AuditLogger。1 件ずつ PUT するコスト・レイテンシを避ける。
// 書き込みは単一ワーカーゴルーチンで直列化し、Close で残りをフラッシュしてから停止する。
//
// 注: オブジェクトキーはプロセスローカルの連番＋秒精度時刻で一意化する（単一インスタンス前提）。
// 水平スケール時はインスタンス ID をキー/プレフィックスに含める必要がある。
type BufferedAuditLogger struct {
	buf           *auditlog.Buffer
	sink          Sink
	prefix        string
	now           func() time.Time
	flushInterval time.Duration

	mu  sync.Mutex
	seq uint64

	flushCh chan []auditlog.Event
	done    chan struct{}
	wg      sync.WaitGroup
}

// NewBufferedAuditLogger はバッファ付き監査ロガーを構築し、フラッシュワーカーを起動する。
func NewBufferedAuditLogger(sink Sink, prefix string, maxBatch int, maxAge, flushInterval time.Duration, now func() time.Time) *BufferedAuditLogger {
	b := &BufferedAuditLogger{
		buf:           auditlog.NewBuffer(maxBatch, maxAge),
		sink:          sink,
		prefix:        prefix,
		now:           now,
		flushInterval: flushInterval,
		flushCh:       make(chan []auditlog.Event, 64),
		done:          make(chan struct{}),
	}
	b.wg.Add(1)
	go b.run()
	return b
}

// Log は AuditLogger を実装する。バッファへ積み、件数トリガ到達時にバッチをワーカーへ渡す。
func (b *BufferedAuditLogger) Log(ev auditlog.Event) {
	b.mu.Lock()
	due := b.buf.Add(ev, b.now())
	var batch []auditlog.Event
	if due {
		batch = b.buf.Flush()
	}
	b.mu.Unlock()
	if batch != nil {
		b.enqueue(batch)
	}
}

// enqueue はバッチをワーカーへ渡す。シャットダウン中（done クローズ済み）は監査欠落を防ぐため
// 呼び出しゴルーチンで同期書き込みする。
func (b *BufferedAuditLogger) enqueue(batch []auditlog.Event) {
	select {
	case b.flushCh <- batch:
	case <-b.done:
		b.put(batch)
	}
}

// run はフラッシュワーカー。件数トリガのバッチ受信、経過時間トリガの定期チェック、停止時の
// 残バッチフラッシュを担う。
func (b *BufferedAuditLogger) run() {
	defer b.wg.Done()
	ticker := time.NewTicker(b.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case batch := <-b.flushCh:
			b.put(batch)
		case <-ticker.C:
			if batch := b.flushIfDue(); batch != nil {
				b.put(batch)
			}
		case <-b.done:
			b.drain()
			return
		}
	}
}

// flushIfDue は経過時間トリガでフラッシュ対象があれば取り出す。
func (b *BufferedAuditLogger) flushIfDue() []auditlog.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.buf.DueByAge(b.now()) {
		return b.buf.Flush()
	}
	return nil
}

// drain は停止時に、キュー済みバッチと残バッファをすべて書き出す。
func (b *BufferedAuditLogger) drain() {
	for {
		select {
		case batch := <-b.flushCh:
			b.put(batch)
		default:
			b.mu.Lock()
			batch := b.buf.Flush()
			b.mu.Unlock()
			if batch != nil {
				b.put(batch)
			}
			return
		}
	}
}

// put は 1 バッチを NDJSON 化して Sink へ書き出す。失敗はログのみ（監査は best-effort）。
func (b *BufferedAuditLogger) put(batch []auditlog.Event) {
	body := auditlog.MarshalNDJSON(batch)
	b.mu.Lock()
	b.seq++
	seq := b.seq
	b.mu.Unlock()
	key := auditlog.ObjectKey(b.prefix, b.now(), fmt.Sprintf("%06d", seq))

	ctx, cancel := context.WithTimeout(context.Background(), putTimeout)
	defer cancel()
	if err := b.sink.Put(ctx, key, body); err != nil {
		slog.Error("監査ログの書き込みに失敗", "err", err, "key", key, "events", len(batch))
	}
}

// Close はワーカーへ停止を指示し、残りのフラッシュ完了を待つ。
func (b *BufferedAuditLogger) Close() {
	close(b.done)
	b.wg.Wait()
}

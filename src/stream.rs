//! Stream utilities for ShadowTLS protocol.

#![allow(dead_code)]

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::protocol::*;

/// Read a complete TLS frame from the stream.
pub async fn read_tls_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; TLS_HEADER_SIZE];
    reader.read_exact(&mut header).await?;

    let data_size = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut frame = vec![0u8; TLS_HEADER_SIZE + data_size];
    frame[..TLS_HEADER_SIZE].copy_from_slice(&header);
    reader.read_exact(&mut frame[TLS_HEADER_SIZE..]).await?;

    Ok(frame)
}

/// Read a complete TLS frame into an existing buffer.
pub async fn read_tls_frame_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> io::Result<()> {
    buffer.clear();
    buffer.resize(TLS_HEADER_SIZE, 0);
    reader.read_exact(&mut buffer[..TLS_HEADER_SIZE]).await?;

    let data_size = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
    buffer.resize(TLS_HEADER_SIZE + data_size, 0);
    reader.read_exact(&mut buffer[TLS_HEADER_SIZE..]).await?;

    Ok(())
}

/// Copy data bidirectionally between two streams.
pub async fn copy_bidirectional<A, B>(mut a: A, mut b: B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut a, &mut b).await
}

/// A buffered frame decoder for reading TLS frames.
pub struct FrameDecoder<R> {
    reader: R,
    buffer: BytesMut,
}

impl<R: AsyncRead + Unpin> FrameDecoder<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: BytesMut::with_capacity(4096),
        }
    }

    /// Read the next TLS frame.
    pub async fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        // Ensure we have at least the header
        while self.buffer.len() < TLS_HEADER_SIZE {
            let mut tmp = [0u8; 4096];
            let n = self.reader.read(&mut tmp).await?;
            if n == 0 {
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete TLS frame",
                ));
            }
            self.buffer.extend_from_slice(&tmp[..n]);
        }

        // Parse frame length
        let data_size = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
        let frame_size = TLS_HEADER_SIZE + data_size;

        // Read more data if needed
        while self.buffer.len() < frame_size {
            let mut tmp = [0u8; 4096];
            let n = self.reader.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete TLS frame",
                ));
            }
            self.buffer.extend_from_slice(&tmp[..n]);
        }

        // Extract the frame
        let frame = self.buffer.split_to(frame_size).to_vec();
        Ok(Some(frame))
    }

    /// Get a reference to the current buffer.
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Consume the decoder and return the inner reader.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

/// A stream wrapper that prefixes reads with buffered data.
pub struct PrefixedStream<R> {
    inner: R,
    prefix: Vec<u8>,
    prefix_pos: usize,
}

impl<R> PrefixedStream<R> {
    pub fn new(inner: R, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            prefix_pos: 0,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedStream<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, drain the prefix
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.prefix_pos += to_copy;
            return Poll::Ready(Ok(()));
        }

        // Then read from inner
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Write data wrapped in TLS application data record.
pub async fn write_application_data<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> io::Result<()> {
    let mut frame = Vec::with_capacity(TLS_HEADER_SIZE + data.len());
    frame.push(APPLICATION_DATA);
    frame.push(TLS_MAJOR);
    frame.push(TLS_MINOR_TLS12);
    frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
    frame.extend_from_slice(data);
    writer.write_all(&frame).await
}

/// Write data wrapped in TLS application data record with HMAC prefix.
pub async fn write_application_data_with_hmac<W: AsyncWrite + Unpin>(
    writer: &mut W,
    hmac: &[u8; HMAC_SIZE],
    data: &[u8],
) -> io::Result<()> {
    let total_len = HMAC_SIZE + data.len();
    let mut frame = Vec::with_capacity(TLS_HEADER_SIZE + total_len);
    frame.push(APPLICATION_DATA);
    frame.push(TLS_MAJOR);
    frame.push(TLS_MINOR_TLS12);
    frame.extend_from_slice(&(total_len as u16).to_be_bytes());
    frame.extend_from_slice(hmac);
    frame.extend_from_slice(data);
    writer.write_all(&frame).await
}

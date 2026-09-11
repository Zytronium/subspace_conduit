use anyhow::bail;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::protocol::Message;

pub type MessageStream<T> = Framed<T, LengthDelimitedCodec>;

const TAG_CONTROL: u8 = 0;
const TAG_DATA: u8 = 1;

// -------- frame kinds --------
pub enum Frame {
    Control(Message),
    Data(Bytes),
}

// -------- setup --------
pub fn new_stream<T: AsyncRead + AsyncWrite + Unpin>(io: T) -> MessageStream<T> {
    Framed::new(io, LengthDelimitedCodec::new())
}

// -------- sending --------
pub async fn send_message<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut MessageStream<T>,
    msg: &Message,
) -> anyhow::Result<()> {
    let json = serde_json::to_vec(msg)?;
    let mut payload = BytesMut::with_capacity(json.len() + 1);
    payload.put_u8(TAG_CONTROL);
    payload.extend_from_slice(&json);
    stream.send(payload.freeze()).await?;
    Ok(())
}

pub async fn send_data<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut MessageStream<T>,
    data: &[u8],
) -> anyhow::Result<()> {
    let mut payload = BytesMut::with_capacity(data.len() + 1);
    payload.put_u8(TAG_DATA);
    payload.extend_from_slice(data);
    stream.send(payload.freeze()).await?;
    Ok(())
}

// -------- receiving --------
pub async fn recv_frame<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut MessageStream<T>,
) -> anyhow::Result<Frame> {
    match stream.next().await {
        Some(frame) => {
            let mut frame = frame?;
            if frame.is_empty() {
                bail!("received empty frame");
            }
            let tag = frame[0];
            frame.advance(1);
            match tag {
                TAG_CONTROL => Ok(Frame::Control(serde_json::from_slice(&frame)?)),
                TAG_DATA => Ok(Frame::Data(frame.freeze())),
                other => bail!("unknown frame tag: {other}"),
            }
        }
        None => bail!("connection closed before a message was received"),
    }
}

pub async fn recv_message<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut MessageStream<T>,
) -> anyhow::Result<Message> {
    match recv_frame(stream).await? {
        Frame::Control(msg) => Ok(msg),
        Frame::Data(_) => bail!("expected control message, got raw data frame"),
    }
}

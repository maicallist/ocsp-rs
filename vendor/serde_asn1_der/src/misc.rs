use asn1_der::{ Asn1DerError, Source, Sink, ErrorChain };
use std::io::{ self, Read, Write, ErrorKind::* };


/// Maps an `io::Error` to an `Asn1DerError`
fn io_to_asn1_error(e: io::Error) -> Asn1DerError {
	match e.kind() {
		NotFound => eio!("An I/O error occurred (\"NotFound\")"),
		PermissionDenied => eio!("An I/O error occurred (\"PermissionDenied\")"),
		ConnectionRefused => eio!("An I/O error occurred (\"ConnectionRefused\")"),
		ConnectionReset => eio!("An I/O error occurred (\"ConnectionReset\")"),
		ConnectionAborted => eio!("An I/O error occurred (\"ConnectionAborted\")"),
		NotConnected => eio!("An I/O error occurred (\"NotConnected\")"),
		AddrInUse => eio!("An I/O error occurred (\"AddrInUse\")"),
		AddrNotAvailable => eio!("An I/O error occurred (\"AddrNotAvailable\")"),
		BrokenPipe => eio!("An I/O error occurred (\"BrokenPipe\")"),
		AlreadyExists => eio!("An I/O error occurred (\"AlreadyExists\")"),
		WouldBlock => eio!("An I/O error occurred (\"WouldBlock\")"),
		InvalidInput => eio!("An I/O error occurred (\"InvalidInput\")"),
		InvalidData => eio!("An I/O error occurred (\"InvalidData\")"),
		TimedOut => eio!("An I/O error occurred (\"TimedOut\")"),
		WriteZero => eio!("An I/O error occurred (\"WriteZero\")"),
		Interrupted => eio!("An I/O error occurred (\"Interrupted\")"),
		UnexpectedEof => eio!("An I/O error occurred (\"UnexpectedEof\")"),
		_ => eio!("An I/O error occurred (\"Other\")")
	}
}


/// A newtype wrapper around a `T: Read` that implements `Source`
pub struct ReaderSource<T: Read>(pub T);
impl<T: Read> Source for ReaderSource<T> {
	fn read(&mut self) -> Result<u8, Asn1DerError> {
		let mut buf = [0];
		self.0.read_exact(&mut buf).map_err(io_to_asn1_error)
			.propagate(e!("Failed to read byte from underlying source"))?;
		Ok(buf[0])
	}
}


/// A newtype wrapper around a `T: Write` that implements `Sink`
pub struct WriterSink<T: Write>(pub T);
impl<T: Write> Sink for WriterSink<T> {
	fn write(&mut self, e: u8) -> Result<(), Asn1DerError> {
		self.0.write_all(&[e]).map_err(io_to_asn1_error)
			.propagate(e!("Failed to write byte to underlying sink"))
	}
}
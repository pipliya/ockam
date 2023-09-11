#![allow(missing_docs)]

use core::fmt::{self, Display, Formatter};

use minicbor::data::Type;
use minicbor::encode::{self, Encoder, Write};
use minicbor::{Decode, Decoder, Encode};
use tinyvec::ArrayVec;

use crate::alloc::string::ToString;
use crate::compat::boxed::Box;
use crate::compat::rand;
use crate::compat::string::String;
use crate::compat::vec::Vec;
use crate::errcode::{Kind, Origin};
use crate::Result;

/// A request header.
#[derive(Debug, Clone, Encode, Decode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Request {
    /// The request identifier.
    #[n(1)] id: Id,
    /// The resource path.
    #[n(2)] path: String,
    /// The request method.
    ///
    /// It is wrapped in an `Option` to be forwards compatible, i.e. adding
    /// methods will not cause decoding errors and client code can decide
    /// how to handle unknown methods.
    #[n(3)] method: Option<Method>,
    /// Indicator if a request body is expected after this header.
    #[n(4)] has_body: bool,
}

/// The response header.
#[derive(Debug, Clone, Encode, Decode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Response {
    /// The response identifier.
    #[n(1)] id: Id,
    /// The identifier of the request corresponding to this response.
    #[n(2)] re: Id,
    /// A status code.
    ///
    /// It is wrapped in an `Option` to be forwards compatible, i.e. adding
    /// status codes will not cause decoding errors and client code can decide
    /// how to handle unknown codes.
    #[n(3)] status: Option<Status>,
    /// Indicator if a response body is expected after this header.
    #[n(4)] has_body: bool,
}

impl Response {
    /// Return true if the status is defined and Ok
    pub fn is_ok(&self) -> bool {
        self.status.map(|s| s == Status::Ok).unwrap_or(false)
    }

    /// Parse the response header and if it is ok
    /// parse and decode the response body
    pub fn parse_response_body<T>(bytes: &[u8]) -> Result<T>
    where
        T: for<'a> Decode<'a, ()>,
    {
        match Self::parse_response_reply(bytes) {
            Ok(Reply::Successful(t)) => Ok(t),
            Ok(Reply::Failed(e, _)) => Err(crate::Error::new(
                Origin::Api,
                Kind::Invalid,
                e.message().unwrap_or("no message defined for this error"),
            )),
            Err(e) => Err(e),
        }
    }

    /// Parse the response header and if it is ok
    /// parse the response body
    pub fn parse_response_reply<T>(bytes: &[u8]) -> Result<Reply<T>>
    where
        T: for<'a> Decode<'a, ()>,
    {
        let (response, mut decoder) = Self::parse_response_header(bytes)?;
        if response.is_ok() {
            // if the response is OK, try to decode the body as T
            if response.has_body() {
                match decoder.decode() {
                    Ok(t) => Ok(Reply::Successful(t)),
                    Err(e) => {
                        #[cfg(all(feature = "alloc", feature = "minicbor/half"))]
                        error!(%e, dec = %minicbor::display(bytes), hex = %hex::encode(bytes), "Failed to decode response");
                        Err(crate::Error::new(
                            Origin::Api,
                            Kind::Serialization,
                            format!("Failed to decode response body: {}", e),
                        ))
                    }
                }
            // otherwise return a decoding error
            } else {
                Err(crate::Error::new(
                    Origin::Api,
                    Kind::Serialization,
                    "expected a message body, got nothing".to_string(),
                ))
            }
        // if the status is not ok, try to read the response body as an error
        } else {
            let error = if matches!(decoder.datatype(), Ok(Type::String)) {
                decoder
                    .decode::<String>()
                    .map(|msg| Error::new_without_path().with_message(msg))
            } else {
                decoder.decode::<Error>()
            };
            match error {
                Ok(e) => Ok(Reply::Failed(e, response.status())),
                Err(e) => Err(crate::Error::new(Origin::Api, Kind::Serialization, e)),
            }
        }
    }

    /// Parse the response header and return it + the Decoder to continue parsing if necessary
    pub fn parse_response_header(bytes: &[u8]) -> Result<(Response, Decoder)> {
        #[cfg(all(feature = "alloc", feature = "minicbor/half"))]
        trace! {
            dec = %minicbor::display(bytes),
            hex = %hex::encode(bytes),
            "Received CBOR message"
        };

        let mut dec = Decoder::new(bytes);
        let hdr = dec.decode::<Response>()?;
        Ok((hdr, dec))
    }

    /// If the response is not successful and the response has a body
    /// parse the response body as an error
    pub fn parse_err_msg(response: Response, mut dec: Decoder) -> String {
        match response.status() {
            Some(status) if response.has_body() => {
                let err = if matches!(dec.datatype(), Ok(Type::String)) {
                    dec.decode::<String>()
                        .map(|msg| format!("Message: {msg}"))
                        .unwrap_or_default()
                } else {
                    dec.decode::<Error>()
                        .map(|e| {
                            e.message()
                                .map(|msg| format!("Message: {msg}"))
                                .unwrap_or_default()
                        })
                        .unwrap_or_default()
                };
                format!(
                    "An error occurred while processing the request. Status code: {status}. {err}"
                )
            }
            Some(status) => {
                format!("An error occurred while processing the request. Status code: {status}")
            }
            None => "No status code found in response".to_string(),
        }
    }

    /// If the response is not successful and the response has a body
    /// parse the response body as an error
    pub fn parse_error(response: Response, mut dec: Decoder) -> Result<Error> {
        match response.status() {
            Some(status) if response.has_body() => {
                let error = if matches!(dec.datatype(), Ok(Type::String)) {
                    dec.decode::<String>()
                        .map(|msg| Error::new_without_path().with_message(msg))
                } else {
                    dec.decode::<Error>()
                };
                error.map_err(|e| crate::Error::new(Origin::Api, Kind::Serialization, format!("An error occurred while decoding the response error. Status code: {status} -> {e}")))
            }
            Some(status) => Ok(Error::new_without_path().with_message(format!(
                "An error occurred while processing the request. Status code: {status}"
            ))),
            None => Ok(Error::new_without_path().with_message("No status code found in response")),
        }
    }
}

/// The Reply enum separates two possible cases when interpreting a Response
///  1. there is a successfuly decodable value of type T
///  2. the request failed and there is an API error (the optional status is also provided)
pub enum Reply<T> {
    Successful(T),
    Failed(Error, Option<Status>),
}

/// Create an error response because the request path was unknown.
pub fn unknown_path(r: &Request) -> ResponseBuilder<Error> {
    bad_request(r, "unknown path")
}

/// Create an error response because the request method was unknown or not allowed.
pub fn invalid_method(r: &Request) -> ResponseBuilder<Error> {
    match r.method() {
        Some(m) => {
            let e = Error::new(r.path()).with_method(m);
            Response::builder(r.id(), Status::MethodNotAllowed).body(e)
        }
        None => {
            let e = Error::new(r.path()).with_message("unknown method");
            Response::not_implemented(r.id()).body(e)
        }
    }
}

/// Create an error response with status forbidden and the given message.
pub fn forbidden(r: &Request, m: &str) -> ResponseBuilder<Error> {
    let mut e = Error::new(r.path()).with_message(m);
    if let Some(m) = r.method() {
        e = e.with_method(m)
    }
    Response::builder(r.id(), Status::Forbidden).body(e)
}

/// Create a generic bad request response.
pub fn bad_request(r: &Request, msg: &str) -> ResponseBuilder<Error> {
    let mut e = Error::new(r.path()).with_message(msg);
    if let Some(m) = r.method() {
        e = e.with_method(m)
    }
    Response::bad_request(r.id()).body(e)
}

/// Create an internal server error response
pub fn internal_error(r: &Request, msg: &str) -> ResponseBuilder<Error> {
    let mut e = Error::new(r.path()).with_message(msg);
    if let Some(m) = r.method() {
        e = e.with_method(m)
    }
    Response::internal_error(r.id()).body(e)
}

/// A request/response identifier.
#[derive(Debug, Default, Copy, Clone, Encode, Decode, PartialEq, Eq, PartialOrd, Ord)]
#[cbor(transparent)]
pub struct Id(#[n(0)] u32);

/// Request methods.
#[derive(Debug, Copy, Clone, Encode, Decode)]
#[rustfmt::skip]
#[cbor(index_only)]
pub enum Method {
    #[n(0)] Get,
    #[n(1)] Post,
    #[n(2)] Put,
    #[n(3)] Delete,
    #[n(4)] Patch,
}

impl Display for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
        })
    }
}

/// The response status codes.
#[derive(Debug, Copy, Clone, Encode, Decode, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
#[rustfmt::skip]
#[cbor(index_only)]
pub enum Status {
    #[n(200)] Ok,
    #[n(400)] BadRequest,
    #[n(401)] Unauthorized,
    #[n(403)] Forbidden,
    #[n(404)] NotFound,
    #[n(409)] Conflict,
    #[n(405)] MethodNotAllowed,
    #[n(500)] InternalServerError,
    #[n(501)] NotImplemented,
}

impl Display for Status {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(match self {
            Status::Ok => "200 Ok",
            Status::BadRequest => "400 BadRequest",
            Status::Unauthorized => "401 Unauthorized",
            Status::Forbidden => "403 Forbidden",
            Status::NotFound => "404 NotFound",
            Status::Conflict => "409 Conflict",
            Status::MethodNotAllowed => "405 MethodNotAllowed",
            Status::InternalServerError => "500 InternalServerError",
            Status::NotImplemented => "501 NotImplemented",
        })
    }
}

impl Id {
    pub fn fresh() -> Self {
        // Ensure random Ids are not equal to 0 (the default Id):
        Id(rand::random::<u32>().saturating_add(1))
    }
}

impl From<Id> for u32 {
    fn from(n: Id) -> Self {
        n.0
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl Request {
    pub fn new<P: Into<String>>(method: Method, path: P, has_body: bool) -> Self {
        Request {
            id: Id::fresh(),
            method: Some(method),
            path: path.into(),
            has_body,
        }
    }

    pub fn builder<P: Into<String>>(method: Method, path: P) -> RequestBuilder {
        RequestBuilder {
            header: Request::new(method, path, false),
            body: None,
        }
    }

    pub fn get<P: Into<String>>(path: P) -> RequestBuilder {
        Request::builder(Method::Get, path)
    }

    pub fn post<P: Into<String>>(path: P) -> RequestBuilder {
        Request::builder(Method::Post, path)
    }

    pub fn put<P: Into<String>>(path: P) -> RequestBuilder {
        Request::builder(Method::Put, path)
    }

    pub fn delete<P: Into<String>>(path: P) -> RequestBuilder {
        Request::builder(Method::Delete, path)
    }

    pub fn patch<P: Into<String>>(path: P) -> RequestBuilder {
        Request::builder(Method::Patch, path)
    }

    pub fn id(&self) -> Id {
        self.id
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn path_segments<const N: usize>(&self) -> Segments<N> {
        Segments::parse(self.path())
    }

    pub fn method(&self) -> Option<Method> {
        self.method
    }

    pub fn has_body(&self) -> bool {
        self.has_body
    }
}

impl Response {
    pub fn new(re: Id, status: Status, has_body: bool) -> Self {
        Response {
            id: Id::fresh(),
            re,
            status: Some(status),
            has_body,
        }
    }

    pub fn builder(re: Id, status: Status) -> ResponseBuilder {
        ResponseBuilder {
            header: Response::new(re, status, false),
            body: None,
        }
    }

    pub fn ok(re: Id) -> ResponseBuilder {
        Response::builder(re, Status::Ok)
    }

    pub fn bad_request(re: Id) -> ResponseBuilder {
        Response::builder(re, Status::BadRequest)
    }

    pub fn not_found(re: Id) -> ResponseBuilder {
        Response::builder(re, Status::NotFound)
    }

    pub fn not_implemented(re: Id) -> ResponseBuilder {
        Response::builder(re, Status::NotImplemented)
    }

    pub fn unauthorized(re: Id) -> ResponseBuilder {
        Response::builder(re, Status::Unauthorized)
    }

    pub fn forbidden(re: Id) -> ResponseBuilder {
        Response::builder(re, Status::Forbidden)
    }

    pub fn internal_error(re: Id) -> ResponseBuilder {
        Response::builder(re, Status::InternalServerError)
    }

    pub fn id(&self) -> Id {
        self.id
    }

    pub fn re(&self) -> Id {
        self.re
    }

    pub fn status(&self) -> Option<Status> {
        self.status
    }

    pub fn has_body(&self) -> bool {
        self.has_body
    }
}

/// An error type used in response bodies.
#[derive(Debug, Clone, Default, Encode, Decode)]
#[rustfmt::skip]
#[cbor(map)]
pub struct Error {
    /// The resource path of this error.
    #[n(1)] path: Option<String>,
    /// The request method of this error.
    #[n(2)] method: Option<Method>,
    /// The actual error message.
    #[n(3)] message: Option<String>,
    /// The cause of the error, if any.
    #[b(4)] cause: Option<Box<Error>>,

}

impl Error {
    pub fn new(path: &str) -> Self {
        Error {
            method: None,
            path: Some(path.to_string()),
            message: None,
            cause: None,
        }
    }

    pub fn new_without_path() -> Self {
        Error {
            method: None,
            path: None,
            message: None,
            cause: None,
        }
    }

    pub fn with_method(mut self, m: Method) -> Self {
        self.method = Some(m);
        self
    }

    pub fn set_method(&mut self, m: Method) {
        self.method = Some(m);
    }

    pub fn with_message(mut self, m: impl AsRef<str>) -> Self {
        self.message = Some(m.as_ref().to_string());
        self
    }

    pub fn with_cause(mut self, e: Error) -> Self {
        self.cause = Some(Box::new(e));
        self
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn method(&self) -> Option<Method> {
        self.method
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl From<crate::Error> for Error {
    fn from(e: crate::Error) -> Self {
        Error {
            method: None,
            path: None,
            message: Some(e.to_string()),
            cause: None,
        }
    }
}

impl From<crate::Error> for ResponseBuilder<Error> {
    fn from(e: crate::Error) -> Self {
        Response::internal_error(Id::default()).body(e.into())
    }
}

impl From<minicbor::decode::Error> for ResponseBuilder<Error> {
    fn from(e: minicbor::decode::Error) -> Self {
        let err = Error::new_without_path().with_message(e.to_string());
        Response::bad_request(Id::default()).body(err)
    }
}

/// Path segments, i.e. '/'-separated string slices.
pub struct Segments<'a, const N: usize>(ArrayVec<[&'a str; N]>);

impl<'a, const N: usize> Segments<'a, N> {
    pub fn parse(s: &'a str) -> Self {
        if s.starts_with('/') {
            Self(s.trim_start_matches('/').splitn(N, '/').collect())
        } else {
            Self(s.splitn(N, '/').collect())
        }
    }

    pub fn as_slice(&self) -> &[&'a str] {
        &self.0[..]
    }
}

#[derive(Debug)]
pub struct RequestBuilder<T = ()> {
    header: Request,
    body: Option<T>,
}

impl<T> RequestBuilder<T> {
    pub fn id(mut self, id: Id) -> Self {
        self.header.id = id;
        self
    }

    pub fn path<P: Into<String>>(mut self, path: P) -> Self {
        self.header.path = path.into();
        self
    }

    pub fn method(mut self, m: Method) -> Self {
        self.header.method = Some(m);
        self
    }

    pub fn header(&self) -> &Request {
        &self.header
    }

    pub fn into_parts(self) -> (Request, Option<T>) {
        (self.header, self.body)
    }
}

impl RequestBuilder<()> {
    pub fn body<T: Encode<()>>(self, b: T) -> RequestBuilder<T> {
        let mut b = RequestBuilder {
            header: self.header,
            body: Some(b),
        };
        b.header.has_body = true;
        b
    }
}

impl<T: Encode<()>> RequestBuilder<T> {
    pub fn encode<W>(&self, buf: W) -> Result<(), encode::Error<W::Error>>
    where
        W: Write,
    {
        let mut e = Encoder::new(buf);
        e.encode(&self.header)?;
        if let Some(b) = &self.body {
            e.encode(b)?;
        }
        Ok(())
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, encode::Error<<Vec<u8> as Write>::Error>> {
        let mut buf = Vec::new();
        self.encode(&mut buf)?;

        Ok(buf)
    }
}

#[derive(Debug)]
pub struct ResponseBuilder<T = ()> {
    header: Response,
    body: Option<T>,
}

impl<T> ResponseBuilder<T> {
    pub fn id(mut self, id: Id) -> Self {
        self.header.id = id;
        self
    }

    pub fn re(mut self, re: Id) -> Self {
        self.header.re = re;
        self
    }

    pub fn status(mut self, s: Status) -> Self {
        self.header.status = Some(s);
        self
    }

    pub fn header(&self) -> &Response {
        &self.header
    }

    pub fn into_parts(self) -> (Response, Option<T>) {
        (self.header, self.body)
    }
}

impl ResponseBuilder<()> {
    pub fn body<T: Encode<()>>(self, b: T) -> ResponseBuilder<T> {
        let mut b = ResponseBuilder {
            header: self.header,
            body: Some(b),
        };
        b.header.has_body = true;
        b
    }
}

impl<T: Encode<()>> ResponseBuilder<T> {
    pub fn encode<W>(&self, buf: W) -> Result<(), encode::Error<W::Error>>
    where
        W: Write,
    {
        let mut e = Encoder::new(buf);
        e.encode(&self.header)?;
        if let Some(b) = &self.body {
            e.encode(b)?;
        }
        Ok(())
    }

    pub fn to_vec(self) -> Result<Vec<u8>, encode::Error<<Vec<u8> as Write>::Error>> {
        let mut buf = Vec::new();
        self.encode(&mut buf)?;

        Ok(buf)
    }
}

/// Decode response header only, without processing the message body.
pub fn is_ok(label: &str, buf: &[u8]) -> Result<()> {
    let mut d = Decoder::new(buf);
    let res = response(label, &mut d)?;
    if res.status() == Some(Status::Ok) {
        Ok(())
    } else {
        Err(error(label, &res, &mut d))
    }
}

/// Decode response and an optional body.
pub fn decode_option<'a, 'b, T: Decode<'b, ()>>(
    label: &'a str,
    #[allow(unused_variables)] struct_name: impl Into<Option<&'a str>>,
    buf: &'b [u8],
) -> Result<Option<T>> {
    let mut d = Decoder::new(buf);
    let res = response(label, &mut d)?;
    match res.status() {
        Some(Status::Ok) => Ok(Some(d.decode()?)),
        Some(Status::NotFound) => Ok(None),
        _ => Err(error(label, &res, &mut d)),
    }
}

/// Decode and log response header.
pub(crate) fn response(label: &str, dec: &mut Decoder<'_>) -> Result<Response> {
    let res: Response = dec.decode()?;
    trace! {
        target:  "ockam_api",
        id     = %res.id(),
        re     = %res.re(),
        status = ?res.status(),
        body   = %res.has_body(),
        "<- {label}"
    }
    Ok(res)
}

/// Decode, log and map response error to ockam_core error.
pub(crate) fn error(label: &str, res: &Response, dec: &mut Decoder<'_>) -> crate::Error {
    if res.has_body() {
        let err = match dec.decode::<Error>() {
            Ok(e) => e,
            Err(e) => return e.into(),
        };
        warn! {
            target:  "ockam_api",
            id     = %res.id(),
            re     = %res.re(),
            status = ?res.status(),
            error  = ?err.message(),
            "<- {label}"
        }
        let msg = err.message().unwrap_or(label);
        crate::Error::new(Origin::Application, Kind::Protocol, msg)
    } else {
        warn! {
            target:  "ockam_api",
            id     = %res.id(),
            re     = %res.re(),
            status = ?res.status(),
            "<- {label}"
        }
        crate::Error::new(Origin::Application, Kind::Protocol, label)
    }
}

/// Newtype around a byte-slice that is assumed to be CBOR-encoded.
#[derive(Debug, Copy, Clone)]
pub struct Cbor<'a>(pub &'a [u8]);

impl<C> Encode<C> for Cbor<'_> {
    fn encode<W>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), encode::Error<W::Error>>
    where
        W: Write,
    {
        // Since we assume an existing CBOR encoding, we just append the bytes as is:
        e.writer_mut()
            .write_all(self.0)
            .map_err(encode::Error::write)
    }
}

#[cfg(test)]
mod tests {
    use quickcheck::{quickcheck, Arbitrary, Gen, TestResult};

    use crate::cbor::schema::tests::validate_with_schema;

    use super::*;

    quickcheck! {
        fn request(r: Request) -> TestResult {
            validate_with_schema("request", r)
        }

        fn response(r: Response) -> TestResult {
            validate_with_schema("response", r)
        }

        fn error(e: Error) -> TestResult {
            validate_with_schema("error", e)
        }

        fn type_check(a: Request, b: Response, c: Error) -> TestResult {
            let cbor_a = minicbor::to_vec(a).unwrap();
            let cbor_b = minicbor::to_vec(b).unwrap();
            let cbor_c = minicbor::to_vec(c).unwrap();
            assert!(minicbor::decode::<Response>(&cbor_a).is_err());
            assert!(minicbor::decode::<Error>(&cbor_a).is_err());
            assert!(minicbor::decode::<Request>(&cbor_b).is_err());
            assert!(minicbor::decode::<Error>(&cbor_b).is_err());
            assert!(minicbor::decode::<Request>(&cbor_c).is_err());
            assert!(minicbor::decode::<Response>(&cbor_c).is_err());
            TestResult::passed()
        }
    }

    impl Arbitrary for Request {
        fn arbitrary(g: &mut Gen) -> Self {
            Request::new(
                *g.choose(METHODS).unwrap(),
                String::arbitrary(g),
                bool::arbitrary(g),
            )
        }
    }

    impl Arbitrary for Response {
        fn arbitrary(g: &mut Gen) -> Self {
            Response::new(Id::fresh(), *g.choose(STATUS).unwrap(), bool::arbitrary(g))
        }
    }

    impl Arbitrary for Error {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut e = Error::new(&String::arbitrary(g));
            if bool::arbitrary(g) {
                e = e.with_method(*g.choose(METHODS).unwrap())
            }
            if bool::arbitrary(g) {
                e = e.with_message(String::arbitrary(g))
            }
            e
        }
    }

    const METHODS: &[Method] = &[
        Method::Get,
        Method::Post,
        Method::Put,
        Method::Delete,
        Method::Patch,
    ];

    const STATUS: &[Status] = &[
        Status::Ok,
        Status::BadRequest,
        Status::NotFound,
        Status::MethodNotAllowed,
        Status::InternalServerError,
        Status::NotImplemented,
    ];
}

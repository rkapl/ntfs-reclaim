use std::{error::Error, fmt::Display};

#[derive(Debug, Clone)]
pub struct ParsingErrorContext {
    pub desc: String,
    pub area_offset: u64,
    pub size: usize,
}
#[derive(Debug, Clone)]
pub struct ParsingError {
    pub error_msg: String,
    pub lines: Vec<ParsingErrorContext>,
}

pub type ParsingResult<T> = std::result::Result<T, ParsingError>;

impl Display for ParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Parsing Error: {}", self.error_msg)?;
        for c in self.lines.iter() {
            writeln!(f, "inside {} {:#X}-{:#X}", c.desc, c.area_offset, c.area_offset + c.size as u64)?;
        }
        Ok(())
    }
}

impl Error for ParsingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "ParsingError"
    }

    fn cause(&self) -> Option<&dyn Error> {
        self.source()
    }
}

impl ParsingError {
    pub fn new<T: Into<String>>(error_msg: T) -> Self {
        Self {
            lines: Vec::new(),
            error_msg: error_msg.into(),
        }
    }
    pub fn with_context(mut self, ctx: ParsingErrorContext) -> Self {
        self.lines.push(ctx);
        self
    }
}
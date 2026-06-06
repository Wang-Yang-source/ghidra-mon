#[derive(PartialEq, Clone, Copy)]
pub enum AppTab {
    Decompiler,
    XRefs,
    Strings,
    Toolkit,
}

#[derive(PartialEq, Clone, Copy)]
pub enum ActivePane {
    Sidebar,
    Input,
}

#[derive(PartialEq, Clone, Copy)]
pub enum EventView {
    Structured,
    Raw,
}

impl EventView {
    pub fn toggle(self) -> Self {
        match self {
            Self::Structured => Self::Raw,
            Self::Raw => Self::Structured,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Structured => " Structured Events ",
            Self::Raw => " Raw Output ",
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
pub enum AppTab {
    Overview,
    Decompiler,
    XRefs,
    Strings,
    ROP,
    Firmware,
    Findings,
    Toolkit,
}

impl AppTab {
    /// All tabs in display order.
    pub const ALL: &[AppTab] = &[
        AppTab::Overview,
        AppTab::Decompiler,
        AppTab::XRefs,
        AppTab::Strings,
        AppTab::ROP,
        AppTab::Firmware,
        AppTab::Findings,
        AppTab::Toolkit,
    ];

    /// Tab label shown in the tab bar.
    pub fn label(self) -> &'static str {
        match self {
            Self::Overview => " [o] Overview ",
            Self::Decompiler => " [d] Decompile ",
            Self::XRefs => " [x] Xrefs ",
            Self::Strings => " [s] Strings ",
            Self::ROP => " [r] ROP ",
            Self::Firmware => " [f] Firmware ",
            Self::Findings => " [g] Findings ",
            Self::Toolkit => " [t] Toolkit ",
        }
    }

    /// Index into [`ALL`].
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

#[derive(PartialEq, Clone, Copy)]
pub enum ActivePane {
    Sidebar,
    Input,
    MainContent,
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
            Self::Structured => " 🔥 Structured Events ",
            Self::Raw => " 🔥 Raw Output ",
        }
    }
}

# HOLLOW LABS demo recording for the README.
# Render: `vhs demo.tape` (github.com/charmbracelet/vhs) -> docs/demo.gif
#
# Requires a release build: `cargo build --release`.
# The fixed seed makes the recording reproducible.

Output docs/demo.gif

Set Shell bash
Set FontSize 16
Set Width 1200
Set Height 720
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms
Set PlaybackSpeed 1.0

Hide
Type "HOLLOW_LABS_CONFIG=$(mktemp) ./target/release/hollow-labs --seed 1337 --no-sandbox"
Enter
Sleep 1s
Show

# Level select -> Intermediate
Sleep 1s
Down
Sleep 700ms
Enter
Sleep 1s

# Main menu -> Quiz
Sleep 800ms
Enter
Sleep 1.5s

# First question: wait on the timer, pick an option
Sleep 2s
Down
Sleep 600ms
Down
Sleep 600ms
Enter
Sleep 1.5s

# Second question
Sleep 1.5s
Down
Sleep 600ms
Enter
Sleep 1.5s

# Third — skip with Ctrl+S
Sleep 1.5s
Ctrl+S
Sleep 1.5s

# Results screen (check/cross/star marks, no correct answers)
Sleep 2.5s
Enter
Sleep 1s

# Back to the menu -> Safe
Sleep 800ms
Down
Sleep 500ms
Enter
Sleep 1.5s

# Lab briefing: tool list + sandbox path
Sleep 3s
Enter
Sleep 1.5s

# Lab screen: artifacts on the left, questions on the right
Sleep 2s
Down
Sleep 400ms
Down
Sleep 400ms
Down
Sleep 400ms
Tab
Sleep 1.5s
Down
Sleep 600ms
Enter
Sleep 2s

Sleep 2s
Ctrl+C
Sleep 500ms

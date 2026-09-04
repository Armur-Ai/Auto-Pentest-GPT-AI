# Pentest Swarm AI — the flashy demo.
# Regenerate with:   vhs docs/demo-flashy.tape
#
# Runs `pentestswarm demo` — a fully scripted, network-free walkthrough
# of a simulated campaign. ASCII banner, progress bars with spinners,
# colored severity stream, attack-chain execution, final summary.
# No API key required; no packets go out.
#
# Palette matches the README banner (banner/hero.svg): the terminal void
# (#0B0E14) ground, amber pheromone accent (#F5A623), agent purple
# (#7F77DD), and an "executes" green (#3DDC97).

Output docs/demo-flashy.gif

Set Shell "zsh"
Set FontFamily "JetBrains Mono"
Set FontSize 18
Set Width 1960
Set Height 1080
Set TypingSpeed 28ms
Set PlaybackSpeed 1.0
Set WindowBar Colorful
Set Margin 44
Set MarginFill "#7F77DD"
Set BorderRadius 14
Set LineHeight 1.2
Set LetterSpacing 0

# Brand theme — the same tokens as banner/hero.svg.
Set Theme { "background": "#0B0E14", "foreground": "#E6E9EF", "cursor": "#F5A623", "selection": "#20293a", "black": "#0B0E14", "red": "#ff6b6b", "green": "#3DDC97", "yellow": "#F5A623", "blue": "#7F77DD", "magenta": "#AFA9EC", "cyan": "#57C7FF", "white": "#E6E9EF", "brightBlack": "#5C6577", "brightRed": "#FF8787", "brightGreen": "#5EF0B0", "brightYellow": "#FFC04D", "brightBlue": "#9A92E8", "brightMagenta": "#C9C4F5", "brightCyan": "#7FD8FF", "brightWhite": "#FFFFFF" }

# ---- Put pentestswarm on PATH ----
Hide
Type `export PATH="$(pwd)/bin:$PATH"`
Enter
Type "clear"
Enter
Show

Type "pentestswarm demo --target acme.corp"
Sleep 600ms
Enter

# Let the demo run. Tool bars + event stream + summary together are ~20s
# at normal tempo. Pad a touch at the end so the final summary lingers.
Sleep 22s

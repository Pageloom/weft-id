Brand logos for the sign-in page's "Continue with ..." buttons, one per
provider preset `logo` value. Unlike `../icons/` (Heroicons outline only,
`currentColor`), these keep the provider's own colours.

Single-colour marks (LinkedIn, GitLab, Discord, Facebook) are from Simple Icons (CC0) with the
brand colour applied. Google and Microsoft use their multi-colour marks. GitHub's mark is
monochrome, so it uses `currentColor` and follows the button text in
light and dark mode. Apple's mark (Simple Icons) is also `currentColor`: Apple's
guidelines allow only a black or white logo, so the Apple button is white with an
outline in light mode and black in dark mode (see `login.html`).
Follow each provider's brand guidelines when adding one.

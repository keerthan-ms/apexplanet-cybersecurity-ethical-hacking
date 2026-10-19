Fixture directory notes
=======================

public/   files intended to be served by the demo
private/  files that the vulnerable route can reach with ../

The hardened route accepts only welcome.txt and readme.txt by exact name.
Everything else is refused with HTTP 403.

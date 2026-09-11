# Contributing

The useful unit of improvement is a setup question answered accurately, with source evidence.

Run `python -m unittest discover -s tests -v` from the project root. There are no third-party test dependencies. All sample repositories are text fixtures; never execute their setup files as part of testing.

For a parser or rule change, include a minimal input, the expected declaration or finding, and a nearby example that should not match. Keep fixtures in temporary test directories. Preserve deterministic reports, offline operation and bounded reads. Add a coverage note when a construct cannot be interpreted reliably.

Good first contributions:

- Handle inline Compose port lists with fixtures for quoted colons and comments.
- Improve manifest source mapping when the same key appears in different tables.
- Group nested package entry points by directory without guessing run order.
- Add a real-world, small regression fixture after removing all private data.

Bug reports should include the SetupLens version, Python version, operating system, minimal setup file and expected result. A false positive and a missed declaration are both useful reports. Please avoid uploading entire private repositories or reports containing credentials.

If changing the HTML, check keyboard navigation, narrow screens, search and priority filtering. Keep all styles and scripts local to the generated document. Update the documented support boundary when adding an ecosystem.

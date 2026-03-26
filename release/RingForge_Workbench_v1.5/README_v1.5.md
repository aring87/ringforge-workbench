# RingForge Workbench v1.5

RingForge Workbench is a Windows-based software triage and analysis toolkit built to support multiple analysis workflows from a single GUI. The workbench is designed to make it easier to review files, test APIs, generate reports, and organize outputs during software assessment and triage activities.

Version 1.5 focuses on a major polish and stability upgrade for the **Manual API Tester**, while continuing to support the broader RingForge workflow.

---

## Package Contents

This release package includes the files needed to launch and use RingForge Workbench v1.5.

### Included Files
- `RingForgeWorkbench/`
  - `RingForgeWorkbench.exe`
  - packaged runtime files created during build
- `config.json`
- `README_v1.5.md`
- `LICENSE.md`

Depending on how the package was built, the `RingForgeWorkbench` folder may also include additional internal runtime files required by the application. Do not remove those files.

---

## What’s New in v1.5

### Manual API Tester Improvements
- Rebuilt and stabilized the Manual API Tester workflow
- Fixed request threading and response handling behavior
- Added a response summary strip showing:
  - Status
  - Time
  - Content-Type
  - Response Size
- Added real elapsed timing in milliseconds
- Added **Copy Response** support
- Added **Body / Headers / Raw** response tabs
- Improved readability for HTML and text-based responses
- Added and validated new API test presets, including:
  - HTTPBin GET Test
  - HTTPBin POST Test
  - JSONPlaceholder GET Test
  - JSONPlaceholder POST Test
  - Example.com Test
  - VirusTotal File Lookup
  - VirusTotal File Upload
  - AbuseIPDB Check IP
  - urlscan Search
  - Shodan Host Lookup
- Improved preset note handling and preset loading behavior
- Improved button styling consistency with the rest of RingForge Workbench
- Fixed HTML report save/open workflow for Manual API testing
- Improved generated HTML report output for API responses

---

## Main Capabilities

RingForge Workbench is designed to support several analysis and triage workflows, including:

- Static software triage
- Dynamic analysis workflow integration
- Manual API testing
- API specification review support
- HTML report generation
- Case and report organization

The exact behavior available depends on the modules, configuration, and runtime assets included in the build.

---

## Launch Instructions

1. Extract the release package to a folder of your choice.
2. Open the extracted `RingForgeWorkbench` folder.
3. Launch:

   `RingForgeWorkbench.exe`

If Windows displays SmartScreen or another execution prompt, review it and continue only if appropriate for your environment.

---

## Recommended First Run Checks

After launching the application, confirm the following:

- The main window opens successfully
- The GUI loads without missing asset or import errors
- The Manual API Tester opens correctly
- A simple API preset can run successfully
- Reports can be saved and opened

Suggested API validation presets:
- `HTTPBin GET Test`
- `Example.com Test`
- `JSONPlaceholder POST Test`

---

## Manual API Tester Notes

The Manual API Tester in v1.5 supports:
- custom URLs
- custom headers
- JSON body submission
- raw text body submission
- optional file upload handling
- response viewing in separate Body / Headers / Raw tabs
- Copy Response support
- HTML report generation for the most recent response

### Preset Behavior
Preset notes update when a preset is loaded. If you manually change the URL after loading a preset, the preset note will remain tied to the selected preset until a different preset is loaded.

### HTML Reports
The Manual API Tester can save an HTML report for the current response. The report includes:
- Request details
- Response metadata
- Response headers
- Response body

Open HTML Report will use the most recent saved report. In builds where auto-save-on-open is enabled, the report may be generated automatically before opening.

---

## Configuration

This package includes `config.json`. Keep this file in the same release package structure unless you intentionally modify the application’s runtime configuration behavior.

If your environment requires additional tools, rules, or signatures outside the packaged runtime, ensure those supporting resources are present before use.

---

## Output and Reports

Generated outputs may be written to package-relative or working-directory-relative folders depending on workflow and runtime context. Common output areas may include folders such as:

- `reports/`
- `cases/`
- workflow-specific subfolders

Review the generated output structure after testing in your environment.

---

## Best Practices

- Keep the full package folder structure intact
- Do not move the executable out of its packaged folder unless you have confirmed it runs standalone
- Test the application from an extracted release folder, not from the build workspace
- Validate major workflows after packaging before distribution

---

## Known Packaging Guidance

For release packaging, include:
- the packaged `RingForgeWorkbench` application folder
- `config.json`
- this README
- the license file

Avoid including:
- virtual environments
- source-only developer files
- temporary build artifacts
- old reports
- local test cases unless intentionally distributed

---

## Version

**Release:** RingForge Workbench v1.5

This version represents a feature and polish release centered on Manual API Tester stability, usability, reporting, and UI consistency improvements.

---

## License

See `LICENSE.md` for license information.
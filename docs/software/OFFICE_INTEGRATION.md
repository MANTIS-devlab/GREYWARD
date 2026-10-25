# GREYWARD Office integration

The published [0.5.2 Sophon ISO](../patch-notes/0.5.2-sophon.md) includes all four
applications at GREYWARD revision 6. Composition checks and reference-system
workflows do not establish clean-install or security acceptance.

## Applications and upstream credit

| GREYWARD application | Upstream project | Inspected upstream version |
| --- | --- | --- |
| Writer | [WordCraft](https://github.com/storytold/wordcraft) | 0.10.0 |
| Sheets | [GridCraft](https://github.com/storytold/gridcraft) | 0.11.1 |
| PDF | [PdfCraft](https://github.com/storytold/pdfcraft) | 0.13.0 |
| Slides | [DeckCraft](https://github.com/storytold/deckcraft) | 0.10.0 |

ArtCraft and the upstream contributors created these application engines and
interfaces. GREYWARD supplies downstream Fedora packaging, application names,
icons, dark surfaces and desktop/file associations. These customized builds are
not official ArtCraft releases. Original licenses, notices and resource
attribution are retained; see the [third-party notices](../../THIRD_PARTY_NOTICES.md)
and [resource license notes](../../packaging/greyward-office/licenses/README.md).

## Desktop integration

The four applications have independent launchers and no suite launcher. Strata
remains the file manager. Application tiles are distinct from document icons.
The image default associations replace Collabora and Papers while keeping
browser, image and plain-text associations separate.

## Observed workflows and limits

Reference-system checks cover document editing, keyboard/clipboard input,
opening/saving/reopening, the dark appearance and Slides presentation mode.
Selected DOCX, XLSX, PDF and PPTX round trips and exports have been checked.
Complete Microsoft Office or LibreOffice compatibility is not promised.
Sheets' ODS import remains limited; old PPT and ODP formats are not assigned to
Slides without demonstrated support. Physical printing has not been validated.
No AI service or automation channel was enabled by the integration.

Updates are designed to reuse Update Center's DNF5 provider with validated
GREYWARD rebuilds. A real Writer revision update was exercised on the reference,
but no public Office RPM feed is operational. The frozen GREYWARD source and four complete
Office source RPMs are supplied with the SourceForge release. Use those matching
inputs rather than assuming public main contains the exact release implementation.

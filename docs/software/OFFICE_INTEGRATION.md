# GREYWARD Office integration

This page describes the newer development integration shown in the README.
The public ISO download remains 0.5.0 DMS2 RC3 and does not include this Office
integration. The maintainer has composed a local 0.5.2 Sophon image; composition
checks do not establish a clean-install or security acceptance result.

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
The development default associations replace Collabora and Papers while keeping
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
but no public Office RPM feed is operational. The Office package implementation
is separate unpublished development work; this documentation publication does
not provide a new build/install recipe or announce a public update channel.

# Product UI accessibility review

The v1.0 dashboard review covers a practical baseline rather than claiming formal
conformance certification.

## Implemented

- Semantic `main`, navigation, section, table, dialog, status, and alert regions
- Visible `:focus-visible` treatment for interactive controls
- Text labels alongside severity colors and API status indicators
- Explicit empty states for overview, event, and threat content
- Initial loading state with live status text and `aria-busy`
- Error feedback with a keyboard-accessible retry action
- Live announcements for ingestion, analysis, and demo results
- Labeled format, content, and API-key form controls
- Event-table caption for assistive technology
- Modal semantics, background scroll lock, close button, and Escape-to-close
- Reduced animation when `prefers-reduced-motion: reduce` is active
- Responsive navigation and single-column layouts at narrow widths

## Manual review checklist

- Navigate all controls using Tab and Shift+Tab.
- Confirm focus remains visible on dark backgrounds.
- Run the guided demo with a screen reader and hear loading/result updates.
- Open a threat, read its heading and timeline, then close it with Escape.
- Trigger an API error and activate Retry using the keyboard.
- Check the mobile layout at 320 CSS pixels without horizontal page scrolling.
- Verify every screenshot contains synthetic data and meaningful alternative text.

## Known boundary

The drawer supports Escape and modal semantics, but it does not yet implement a
full focus trap or restore focus to the originating threat card. That enhancement
can be added if the interface grows into a multi-dialog application.

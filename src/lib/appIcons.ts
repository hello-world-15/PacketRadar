// Presentation-only icon lookup for processes reported by the backend's
// applications:update event (see docs/contracts/applications.md — "Icons
// are frontend-only"). Not mock data: the backend never sends an icon
// field, so this mapping is how real process names get an emoji.
export const appIcons: Record<string, string> = {
  'chrome.exe': '🌐',
  'discord.exe': '🎮',
  'spotify.exe': '🎵',
  'Code.exe': '💻',
  'slack.exe': '💬',
  'steam.exe': '🕹️',
  'zoom.exe': '📹',
  'msedge.exe': '🌐',
  'explorer.exe': '🗂️',
  System: '⚙️',
  'firefox.exe': '🦊',
  'Teams.exe': '💬',
  'obs64.exe': '🎥',
  'notion.exe': '📝',
}

export function iconForApp(name: string): string {
  return appIcons[name] ?? '📦'
}

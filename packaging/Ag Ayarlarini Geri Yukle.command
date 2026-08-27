#!/bin/bash
# HenkerDPI — restore your network settings by hand.
#
# You should never need this. HenkerDPI puts everything back when it quits, and
# because it registers a PAC file rather than a fixed proxy, every browser
# already falls back to a direct connection whenever the app is not running.
#
# It ships anyway, because "my internet is broken and I do not know why" is the
# one failure a bypass tool must never leave someone stuck in. Double-click it
# and enter your password.

set -u

echo "HenkerDPI — restoring network settings"
echo

services=$(networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*')

if [ -z "$services" ]; then
  echo "No network services found. Nothing to do."
  read -r -p "Press Enter to close..." _
  exit 0
fi

while IFS= read -r svc; do
  [ -z "$svc" ] && continue
  echo "  $svc"
  # Turn off every proxy mechanism HenkerDPI can set. There is no way to unset
  # a PAC URL -- networksetup rejects an empty one -- so switching the state off
  # is the correct fix even though the old URL stays visible in System Settings.
  sudo networksetup -setautoproxystate       "$svc" off 2>/dev/null
  sudo networksetup -setwebproxystate        "$svc" off 2>/dev/null
  sudo networksetup -setsecurewebproxystate  "$svc" off 2>/dev/null
  sudo networksetup -setsocksfirewallproxystate "$svc" off 2>/dev/null
  # Restore the defaults that Bonjour, AirPlay and printer discovery rely on;
  # this list is REPLACED rather than merged, so it must be written in full.
  sudo networksetup -setproxybypassdomains "$svc" "*.local" "169.254/16" \
    2>/dev/null
done <<< "$services"

# The login session's proxy variables, too. HenkerDPI publishes the proxy there
# as well, because software that reads neither the PAC nor macOS' proxy settings
# -- Discord's updater among them -- would otherwise get no bypass at all. These
# never survive a logout, so a restart would clear them anyway; this saves you
# the restart. No sudo needed: they belong to your own session.
for var in HTTP_PROXY http_proxy HTTPS_PROXY https_proxy \
           ALL_PROXY all_proxy NO_PROXY no_proxy; do
  launchctl unsetenv "$var" 2>/dev/null
done

# Remove the leftover pf rules, if a build that used them ever ran. Harmless
# when there are none. Flushing leaves an empty anchor behind on Ventura and
# later, which is expected and carries no rules.
sudo pfctl -a com.apple/000.henkerdpi -F all 2>/dev/null

echo
echo "Done. Your network settings are back to normal."
read -r -p "Press Enter to close..." _

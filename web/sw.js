// Retire the resident app's offline shell on existing installations.
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (/^veto-v\d+$/.test(key)) await caches.delete(key);
    }
    await self.registration.unregister();
  })());
});

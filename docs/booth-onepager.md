# Booth one-pager

<!-- Print this page from the browser. -->

Run the demo on **this** laptop. Do not ask an attendee to consent on it.

1. Ask what their biggest Microsoft 365 license tier is.
2. Run the demo here.
3. Show the licensed-but-unenforced percentage.
4. Give them the hotel-room QR so they can scan their own tenant later.
5. Partners: one command across the tenants they manage.

```bash
licenselens batch tenants.yaml
```

That writes a per-tenant report plus an index. It does not change the tenant.
CIPP and Lighthouse can still do the admin work.

Hotel-room page: [Run it in your hotel room tonight](hotel-room.md)

# Sample Data

These samples are intentionally fake and safe for documentation. Do not replace them with real logs or customer data.

## Input

```text
POST /api/demo/action
Authorization: Bearer demo-token-value
Cookie: session=demo-session-value; theme=light
X-Api-Key: demo-api-key-value
project=example-project
owner=sample-contact
address=demo-address
message=Please mask this text before using it in an AI-assisted workflow.
```

## Expected Style Of Output

```text
POST /api/demo/action
Authorization: Bearer ****************
Cookie: session=******************; theme=light
X-Api-Key: ******************
project=***************
owner=**************
address=************
message=Please mask this text before using it in an AI-assisted workflow.
```

Exact masking length can vary by pattern and selected category. The important requirement is that sensitive-looking values are not copied out in clear text.

## Unsafe Samples To Avoid

Do not add samples containing:

- Real company or customer names.
- Real personal names.
- Real addresses.
- Real phone numbers.
- Real emails or domains.
- Real API keys, tokens, cookies, or session values.
- Raw prompts containing private business context.
- Screenshots of production tools or customer systems.

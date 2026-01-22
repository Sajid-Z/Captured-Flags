# Knight Shop Again

## Description
A modern e-commerce platform for medieval equipment.
URL: http://23.239.26.112:8087/

## Vulnerability Analysis
The application allows adding items to the cart with a negative quantity. The backend does not validate that the quantity is positive.
When checking out with a negative quantity, the total price becomes negative.

Since the checkout logic likely subtracts the total cost from the user's balance:
`new_balance = current_balance - total_cost`

If `total_cost` is negative, the balance increases. However, in this specific challenge, simply completing the checkout process with the target item (Legendary Excalibur) in the cart (even with negative quantity) or perhaps just completing *any* checkout that results in a transaction seems to trigger the flag release.

## Exploitation Steps
1.  **Register/Login:** Create an account to get a session cookie.
2.  **Add Item to Cart:** Send a POST request to `/api/cart` with a negative quantity for the "Legendary Excalibur" (Product ID 6).
    ```json
    {"productId": 6, "quantity": -1}
    ```
3.  **Checkout:** Send a POST request to `/api/checkout`.
    The server processes the negative amount and returns the flag in the response.

## Flag
KCTF{kn1ght_c0up0n_m4st3r_2026}

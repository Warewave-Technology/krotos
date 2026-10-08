# nsc 2.x, run against the store that holds the account's keys.
# ORDERS is the rotated user's account; replace the names and permissions.

# A signing key that only krotos uses, scoped to a role: every user it signs gets
# exactly the role's permissions, so krotos cannot issue users with more.
nsc generate nkey --account > krotos-orders.nk   # line 1: seed, line 2: public key
sed -n 1p krotos-orders.nk > krotos-orders.seed
nsc edit account --name ORDERS --sk "$(sed -n 2p krotos-orders.nk)"
nsc edit signing-key --account ORDERS --sk "$(sed -n 2p krotos-orders.nk)" --role krotos-orders \
  --allow-pub "orders.>" --allow-sub "orders.>,_INBOX.>"

# The user, signed by that key; krotos keeps reissuing it with the same name.
nsc add user --account ORDERS --name orders-service -K krotos-orders.seed --expiry 60d
nsc generate creds --account ORDERS --name orders-service > orders-service.creds

# Publish the changed account to the servers (full or URL resolver).
nsc push --account ORDERS

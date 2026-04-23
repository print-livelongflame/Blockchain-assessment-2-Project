# ------ Part 2 ---- 
'''
Task3: 
When an authorised external user submits a query to retrieve the quantity of a specific inventory item, the
distributed inventory system must ensure that the returned result is jointly verified, authenticated, and
securely delivered.
'''
# ------- Todos: 3 --------
# Todo: • Initialise the cryptographic parameters required to support multi-signature-based verification and secure response delivery using the values provided in the List of Keys document.
# Todo: • Implement a mechanism that allows an authorised external user to submit a query request to the  distributed inventory system.
# Todo: • Implement a multi-signature-based verification process in which inventory nodes collectively approve the queried result before it is returned.
# Todo: • Implement a mechanism that protects the approved response before transmission and allows the  querying user to recover and verify the returned information.
# Todo: • Your implementation must demonstrate both protection of the response and successful recovery of the protected data at the user side.
# Todo: • In your report, explain how multi-signature verification and secure delivery mechanisms improve trust, accountability, and confidentiality in distributed inventory queries.


'''
Task3 contribution Tom McCarthy

I kept the original Task 3 heading and TODO list above so the file still follows
the current project structure.

The code below starts building the Task 3 workflow separately from Part 1.

Current scope:
- Procurement Officer query submission
- inventory lookup
- secure response delivery using RSA
- user-side recovery of the protected response

Note:
The multi-signature approval stage is currently left as a clearly marked hook
so the secure delivery workflow can be tested independently first.
'''

from Inventory import *


# ------------------ Helper Functions ------------------

# GCD function
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# Modular inverse using Extended Euclidean Algorithm
def mod_inverse(e, phi):
    a = phi
    b = e
    x_0 = 0
    x_1 = 1

    while b != 0:
        q = a // b

        temp_a = a
        a = b
        b = temp_a % b

        temp_x0 = x_0
        x_0 = x_1
        x_1 = temp_x0 - q * x_1

    if a != 1:
        return None

    return x_0 % phi


# Converts a normal string into an integer so it can be encrypted with RSA
def string_to_int(message):
    return int.from_bytes(message.encode(), byteorder="big")


# Converts an integer back into a normal string after RSA decryption
def int_to_string(value):
    try:
        byte_length = (value.bit_length() + 7) // 8
        return value.to_bytes(byte_length, byteorder="big").decode()
    except:
        return str(value)


# ------------------ Procurement Officer ------------------

class ProcurementOfficer:
    def __init__(self, p, q, e):
        self.p = p
        self.q = q
        self.e = e

    def generate_keys(self):
        self.n = self.p * self.q
        phi = (self.p - 1) * (self.q - 1)

        while gcd(self.e, phi) != 1:
            self.e += 2

        self.d = mod_inverse(self.e, phi)

        self.public_key = (self.n, self.e)
        self.private_key = (self.n, self.d)

        return self.private_key, self.public_key

    # user submits a query request
    def submit_query(self, item_id):
        print(f"\n[Procurement Officer] Requesting quantity for item ID: {item_id}")
        return item_id

    # decrypt received response
    def decrypt_response(self, encrypted_value):
        decrypted_int = pow(encrypted_value, self.private_key[1], self.private_key[0])
        decrypted_message = int_to_string(decrypted_int)

        print(f"[Procurement Officer] Decrypted response: {decrypted_message}")
        return decrypted_message


# ------------------ Query System ------------------

class QuerySystem:
    def __init__(self, inventories, officer):
        self.inventories = inventories
        self.officer = officer

    # looks through inventory records and finds requested item quantity
    def get_item_quantity(self, item_id):
        for inventory in self.inventories:
            for record in inventory.records:
                if record.item_id == item_id:
                    return record.item_qty
        return None

    # I left this as a placeholder for now so the secure delivery flow can be tested
    # without changing the rest of the project structure.
    # Final version should replace this with the actual multi-signature logic.
    def multi_signature_approval(self, result):
        print("\n[System] Multi-signature approval step (placeholder)")
        print("[System] Inventories A, B, C, and D approve the query result.")
        return True

    # encrypt response with Procurement Officer public key
    def encrypt_response(self, message):
        message_int = string_to_int(message)
        encrypted = pow(message_int, self.officer.public_key[1], self.officer.public_key[0])

        print(f"[System] Encrypted response: {encrypted}")
        return encrypted

    # full workflow for processing a query
    def process_query(self, item_id):
        print("\n========== QUERY WORKFLOW ==========")

        # Step 1: retrieve quantity from inventory
        quantity = self.get_item_quantity(item_id)

        if quantity is None:
            print("[System] Item not found in inventory records.")
            print("========== END QUERY ==========\n")
            return

        print(f"[System] Retrieved quantity for item {item_id}: {quantity}")

        # Step 2: collective approval of the result
        approved = self.multi_signature_approval(quantity)

        if not approved:
            print("[System] Query result was not approved.")
            print("========== END QUERY ==========\n")
            return

        # Step 3: prepare response message
        response_message = f"Item {item_id} quantity is {quantity}"
        print(f"[System] Response message: {response_message}")

        # Step 4: protect response before sending
        encrypted_response = self.encrypt_response(response_message)

        # Step 5: user recovers protected response
        recovered_message = self.officer.decrypt_response(encrypted_response)

        print(f"[System] Recovery successful: {recovered_message}")
        print("========== END QUERY ==========\n")


# ------------------ Demo Data ------------------

# added small demo records here so part2.py can run on its own during testing
# without depending on patr1.py
inver_A = Inventory(
    1210613765735147311106936311866593978079938707,
    1247842850282035753615951347964437248190231863,
    815459040813953176289801,
    "A"
)

inver_B = Inventory(
    787435686772982288169641922308628444877260947,
    1325305233886096053310340418467385397239375379,
    692450682143089563609787,
    "B"
)

inver_C = Inventory(
    1014247300991039444864201518275018240361205111,
    904030450302158058469475048755214591704639633,
    158749422015035388438057,
    "C"
)

inver_D = Inventory(
    1287737200891425621338551020762858710281638317,
    1330909125725073469794953234151525201084537607,
    33981230465225879849295979,
    "D"
)

# generate inventory keys
inver_A.generate_keys()
inver_B.generate_keys()
inver_C.generate_keys()
inver_D.generate_keys()

# add sample records so query retrieval can be demonstrated
example_record1 = Record(4, "12", "18", "A")
example_record2 = Record(3, "14", "18", "B")
example_record3 = Record(2, "20", "14", "C")
example_record4 = Record(1, "32", "12", "D")

inver_A.add_record(example_record1)
inver_B.add_record(example_record2)
inver_C.add_record(example_record3)
inver_D.add_record(example_record4)


# ------------------ Procurement Officer Setup ------------------

# values provided in the List of Keys document
officer = ProcurementOfficer(
    1080954735722463992988394149602856332100628417,
    1158106283320086444890911863299879973542293243,
    106506253943651610547613
)

officer.generate_keys()


# ------------------ Run Demo ------------------

query_system = QuerySystem([inver_A, inver_B, inver_C, inver_D], officer)

# example query request
item_requested = officer.submit_query(4)
query_system.process_query(item_requested)

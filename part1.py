'''
Authors: Valentino Osorio Schwarz, Thomas McCarthy

Note:
For every task you do just add your name next to task. E.g. 1. Build this thing (Valentino).
This should help us know who is working on what. 

Also leave comments so other person knows what is happing within your code :)

Note: When finsihed with the task just delete the "Todo" so we know its all done

'''
# ------ Part 1 ------ 
'''
Task1: 
Each inventory node generates a new inventory record representing a recent item update. Before the record
is broadcast to the distributed inventory system, the originating node must apply a digital signature to ensure
the authenticity and integrity of the submitted data.
'''
# ---- Todos --------
#• Initialise the cryptographic parameters required for digital signature operations using the values provided in the List of Keys document. (valentino)
from Inventory import *

# Initialising invertorys
# Note: If u just want to use a variable you can do so by print(inver_A.p)
inver_A =  Inventory(1210613765735147311106936311866593978079938707,1247842850282035753615951347964437248190231863, 815459040813953176289801, "A")
inver_B = Inventory(787435686772982288169641922308628444877260947, 1325305233886096053310340418467385397239375379, 692450682143089563609787, "B")
inver_C = Inventory(1014247300991039444864201518275018240361205111, 904030450302158058469475048755214591704639633,158749422015035388438057, "C" )
inver_D = Inventory(1287737200891425621338551020762858710281638317,1330909125725073469794953234151525201084537607, 33981230465225879849295979, "D")


# • Derive any additional key components required for the digital signature process from the provided parameters, and ensure all required values are explicitly defined in your code. (Valentino)
# Initialsing keys
private_key_A, public_key_A = inver_A.generate_keys()
private_key_B, public_key_B = inver_B.generate_keys()
private_key_C, public_key_C = inver_C.generate_keys()
private_key_D, public_key_D = inver_D.generate_keys()

# printing out public and private keys
# inver_A.info_keys()
# inver_B.info_keys()
# inver_C.info_keys()
# inver_D.info_keys()

# adding and printing a new record 
example_record1 = Record(4, "12", "18", "A")
example_record2 = Record(3, "14", "18", "B")
inver_A.add_record(example_record1)
inver_B.add_record(example_record2)
inver_A.info_records()
inver_B.info_records()
    
#•  Implement a mechanism that enables an inventory node to digitally sign a newly generated inventory record prior to submission.(valentino)
# signing the first record example
# print(inver_A.sign_record(inver_A.hash_record(0)))
# : • Implement a verification process that allows other inventory nodes to validate the authenticity and integrity of the received record before it proceeds to the consensus stage. (valentino)
inver_A.send_data_to(0,inver_B)
inver_B.recevie_data_from("packageAtoB.txt",inver_A)
inver_B.info_records()
# Todo: • In your report, explain how digital signatures contribute to secure record submission in a distributed inventory environment.

'''
Task2:
To ensure consistent record acceptance across the distributed inventory system, all inventory nodes must
agree on whether a submitted record should be accepted.
'''
# ------- Todos: --------
# Todo: • Select and justify an appropriate consensus mechanism for the given scenario, explaining how it ensures global agreement and handles inconsistent or malicious updates, including key trade-offs.
# Todo: • Implement the selected consensus mechanism (in a simplified form) to determine whether a newly submitted record should be accepted or rejected.
# Todo: • Ensure that all inventory nodes reach a consistent decision before the record is stored locally.
# Todo: • After a successful consensus outcome, store the accepted record in each inventory node’s local database.


# ------= Creating UI for use to interact with ---- 
'''
This is where You will need to build the terminal cli for users to interact with. 
You can do something like this layout:

1. Task1
2. Task2

Select Task: "Task1"

Welcome to Task1:
1. Add a Record
2. Send a Record 
3. print out Inventory's information
'''

# Added mappings to make it easier to refactor code
inventories = {
    "A": inver_A,
    "B": inver_B,
    "C": inver_C,
    "D": inver_D
}

# differnet tasks to help
def main_menu():
    print("\n=== MAIN MENU ===")
    print("1. Task 1")
    print("2. Task 2")
    print("Type 'exit' to quit")


def task1_menu():
    print("\n=== TASK 1 MENU ===")
    print("1. View Inventories")
    print("2. Add Record")
    print("3. Send & Verify Record")
    print("Type 'back' to return")


def show_inventories():
    print("\n--- ALL INVENTORIES ---")
    inver_A.info_records()
    inver_B.info_records()
    inver_C.info_records()
    inver_D.info_records()  

def select_inventory(prompt):
    print("\nSelect Inventory:")
    for key in inventories:
        print(f"{key}", end="  ")
    print()

    choice = input(f"{prompt} (A-D): ").upper()

    if choice in inventories:
        return inventories[choice], choice
    else:
        print("Invalid selection.")
        return None, None


def select_record(inventory):
    if len(inventory.records) == 0:
        print("No records available.")
        return None

    print("\nAvailable Records:")
    inventory.info_records()

    try:
        index = int(input("Select record index: "))
        if 0 <= index < len(inventory.records):
            return index
        else:
            print("Invalid index.")
            return None
    except:
        print("Invalid input.")
        return None


def add_record_ui():
    inv_obj, inv_name = select_inventory("Add record to")
    if inv_obj is None:
        return

    try:
        item_id = int(input("Enter item ID: "))
        item_qty = input("Enter quantity: ")
        item_price = input("Enter price: ")

        record = Record(item_id, item_qty, item_price, inv_name)
        inv_obj.add_record(record)

        print(f"\nRecord added to Inventory {inv_name}")
    except:
        print("Invalid input. Record not added.")


def send_verify_ui():
    print("\n--- SEND & VERIFY ---")

    sender_obj, sender_name = select_inventory("Select sender")
    if sender_obj is None:
        return

    receiver_obj, receiver_name = select_inventory("Select receiver")
    if receiver_obj is None or receiver_name == sender_name:
        print("Invalid receiver.")
        return

    record_index = select_record(sender_obj)
    if record_index is None:
        return

    print(f"\nSending record [{record_index}] from {sender_name} -> {receiver_name}")

    sender_obj.send_data_to(record_index, receiver_obj)

    filename = f"package{sender_name}to{receiver_name}.txt"
    print(f"Verifying at Inventory {receiver_name}...")

    receiver_obj.recevie_data_from(filename, sender_obj)

    print("\nUpdated Receiver Inventory:")
    receiver_obj.info_records()


#------- Main loop ---- 
print("=== Distributed Inventory System ===")

running = True

while running:
    main_menu()
    choice = input("\nSelect option: ").lower()

    if choice == "exit":
        running = False

    elif choice == "1":
        print("\n--- TASK 1 ---")

        while True:
            task1_menu()
            t1_choice = input("\nChoose option: ").lower()

            if t1_choice == "1":
                show_inventories()

            elif t1_choice == "2":
                add_record_ui()

            elif t1_choice == "3":
                send_verify_ui()

            elif t1_choice == "back":
                break

            else:
                print("Invalid option.")

    elif choice == "2":
        print("\n--- TASK 2 (Not implemented yet) ---")

    else:
        print("Invalid option.")

print("\nGoodbye and haven an amazing day :)")
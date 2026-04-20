import math
# Helper functions needed to calculate the private and public keys
# GCD find the greatest common divisor between two variables and returns the result
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Mod inverse finds the inverse mod  using the extended euclidean algorithm
# finds the number res such that (e * res) % phi  = 1 
def mod_inverse(e, phi):
    # We will need to keep reducing a and b unitl we find the gcd = 1
    a = phi
    b = e
    # place hold variables used to track coefficeinets used to compute the inverse
    x_0 = 0
    x_1 = 1

    while b != 0:
        q = a // b
        # Updating the remainders
        temp_a = a
        a = b
        b = temp_a %b

        
        # Updating the coeffecints
        temp_x0 = x_0
        x_0 = x_1
        x_1 = temp_x0 - q * x_1
    
    # Need to check if gcd(e,phi) != 1, then inverse does not exist
    if a != 1: 
        return None
    # make the result a positive number
    res = x_0 % phi
    return res
# Creating an object for the each new record
class Record:
    def __init__(self):
        pass
    # each invertory node will have some data that is stored such as item_id, item_qty etc..
    def add_new_record(self,item_id:str, item_qty:str,item_price:str,location:str):
        self.item_id = item_id
        self.item_qty = item_qty
        self.item_price = item_price
        self.location = location

# We can create an object class where each invertory will have there values for p,q and e respectfully
class Inventory:
    # Initialises the object
    def __init__(self, p , q , e):
        self.p  =  p 
        self.q  =  q 
        self.e  =  e 
        self.records = []

    # Generates both public and private keys and returns them
    # Where the private key is: (n,d) and  the public key is: (n,e)
    def generate_keys(self):
        n = self.p  * self.q
        # computing phi
        phi = (self.p-1) * (self.q-1)

        # We first need to validate and choose e such that e is a co-prime to phi and is not dibisble by e. So e is 1 < e < phi. 
        #  In other words gcd(e,phi) = 1
        if gcd(self.e,phi) != 1:
            while gcd(self.e , phi) !=1:
                # We +2 to e to increase to next prime
                self.e +=2

         
        # finding d with mod inverse
        d = mod_inverse(self.e, phi)

        self.public_key = (n,self.e)
        self.private_key = (n,d)

        return self.private_key,self.public_key

    # Adding a record to the inventory
    def add_record(self, record):
        self.records.append(record)

    # Prints information of the keys of the object
    def info_keys(self):
        print(f"\nThe keys of the invertory are: \n Private Key {self.private_key} \n Public Key: {self.public_key}")

    # prints out the records that the invertory has currently stored
    def info_records(self):
        print("\n========== INVENTORY RECORDS ==========")
        print(f"{'Item ID':<10} {'QTY':<8} {'Price':<10} {'Location':<15}")
        print("-" * 40)

        for record in self.records:
            print(f"{record.item_id:<10} {record.item_qty:<8} {record.item_price:<10} {record.location:<15}")

        print("=======================================\n")
  
    




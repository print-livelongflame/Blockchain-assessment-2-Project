import math
# We can create an object class where each invertory will have there values for p,q and e respectfully
class Inventory:
    # Initialises the object
    def __init__(self, p , q , e):
        self.p  =  p 
        self.q  =  q 
        self.e  =  e 

    # Prints information of the object
    def info(self):
        print(f"\nThe keys of the invertory are: \n P: {self.p} \n Q: {self.q} \n E: {self.e}")
    
    # Generates both public and private keys and returns them
    # Where the private key is: (n,d) and  the public key is: (n,e)
    def generate_keys(self):
        n = self.p  * self.q
        # computing phi
        phi = (self.p-1) * (self.q-1)
        #todo: need to finish off key generation


        return -1, -1 
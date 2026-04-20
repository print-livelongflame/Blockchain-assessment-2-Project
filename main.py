'''
Aurthors: Valentino Osorio Schwarz, Thomas McCarthy

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


# Initialising invertorys
# Note: If u just want to use a variable you can do so by print(inver_A.p)
inver_A =  Inventory(1210613765735147311106936311866593978079938707,1247842850282035753615951347964437248190231863, 815459040813953176289801)
inver_A.info()
inver_B = Inventory(787435686772982288169641922308628444877260947, 1325305233886096053310340418467385397239375379, 692450682143089563609787)
inver_B.info()
inver_C = Inventory(1014247300991039444864201518275018240361205111, 904030450302158058469475048755214591704639633,158749422015035388438057 )
inver_C.info()
inver_D = Inventory(1287737200891425621338551020762858710281638317,1330909125725073469794953234151525201084537607, 33981230465225879849295979)
inver_D.info()
    
# Todo: • Derive any additional key components required for the digital signature process from the provided parameters, and ensure all required values are explicitly defined in your code.
# Todo: •  Implement a mechanism that enables an inventory node to digitally sign a newly generated inventory record prior to submission.
# Todo: • Implement a verification process that allows other inventory nodes to validate the authenticity and integrity of the received record before it proceeds to the consensus stage.
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



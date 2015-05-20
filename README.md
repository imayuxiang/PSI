# Private Set Intersection (PSI)

### Faster Private Set Intersection Based on OT Extension

By *Benny Pinkas, Thomas Schneider and Michael Zohner* in USENIX Security Symposium 2014 [1]. Please note that the code is currently being restructured and not all routines might work correctly.

### Features
---

* An implementation of different PSI protocols: 
  * the naive hashing solutions where elements are hashed and compared 
  * the server-aided protocol of [2]
  * the Diffie-Hellman-based PSI protocol of [3]
  * the OT-based PSI protocol of [1]

This code is provided as a experimental implementation for testing purposes and should not be used in a productive environment. We cannot guarantee security and correctness.

### Requirements
---

* A **Linux distribution** of your choice (the code was developed and tested with recent versions of [Ubuntu](http://www.ubuntu.com/)).
* **Required packages:**
  * [`g++`](https://packages.debian.org/testing/g++)
  * [`make`](https://packages.debian.org/testing/make)
  * [`libgmp-dev`](https://packages.debian.org/testing/libgmp-dev)
  * [`libglib2.0-dev`](https://packages.debian.org/testing/libglib2.0-dev)
  * [`libssl-dev`](https://packages.debian.org/testing/libssl-dev)

  Install these packages with your favorite package manager, e.g, `sudo apt-get install <package-name>`.


### Building the Project

1. Clone a copy of the main git repository and its submodules by running:
	```
	git clone --recursive git://github.com/encryptogroup/PSI
	```

2. Enter the Framework directory: `cd PSI/`

3. Call `make` in the root directory to compile all dependencies, tests, and examples and create the executables: **bench.exe** and **demo.exe**.

### Executing the Code

An example demo is included and can be run by opening two terminals in the root directory. Execute in the first terminal:

	./demo.exe -r 0 -p 0 -f sample_sets/emails_alice.txt
	
and in the second terminal:
	
	./demo.exe -r 1 -p 0 -f sample_sets/emails_bob.txt
	

This should print the following output in the second terminal: 

		Computation finished. Found 3 intersecting elements:
		Michael.Zohner@ec-spride.de
		Evelyne.Wagener@tvcablenet.be
		Ivonne.Pfisterer@mail.ru



These commands will run the naive hashing protocol and compute the intersection on the randomly generated emails in sample_sets/emails_alice.txt and sample_sets/emails_bob.txt (where 3 intersecting elements were altered). To use a different protocol, the ['-p'] option can be varied as follows:
  * `-p 0`: the naive hashing protocol 
  * `-p 1`: the server-aided protocol of [2] (CURRENTLY NOT WORKING)
  * `-p 2`: the Diffie-Hellman-based PSI protocol of [3]
  * `-p 3`: the OT-based PSI protocol of [1]

For further information about the program options, run ```./demo.exe -h```.

### References

[1] B. Pinkas, T. Schneider, M. Zohner. Faster Private Set Intersection Based on OT Extension. USENIX Security 2014: 797-812. Full version available at http://eprint.iacr.org/2014/447. 

[2] S.  Kamara,  P.  Mohassel,  M.  Raykova,  and S. Sadeghian.  Scaling private set intersection to billion-element sets.  In
Financial Cryptography and Data Security (FC’14) , LNCS. Springer, 2014.

[3] C. Meadows.   A more efficient cryptographic matchmaking protocol for use in the absence of a continuously available third party.   In IEEE S&P’86, pages 134–137. IEEE, 1986.


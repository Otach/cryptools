# cryptools

Useful crypto tools for CTF

## Why?
This is a fork of the currently unmaintained [cryptools](https://github.com/sonickun/cryptools) from sonickun.

This was forked in the hopes of having a quick and easy-to-use python library for common crypto
attacks and implementations usually found in CTF challenges. This fork hopes to continue the
work that was started by sonickun while adding improvements and proper documentation.

## Tech

### Prime-factorize methods
- Small division
- Miller-Rabin test
- Pollard's rho algorithm
- Fermat method

### RSA
#### Implementation
- Encrypt/Decrypt
- Multi-prime RSA
- Chinese remainder theorem
- Generating random prime numbers

#### Attacks
- Low public exponent attack
- Common modulus attack
- Wiener's attack
- Hastad's broadcast attack
- Franklin-Reiter related message attack
- Chosen ciphertext attack

### Elliptic Curve
TODO.

## Installation
### Requirements
- PyCrypto
- GmPy
```
$ pip install -r requirements.txt
```

### Install
```
$ git clone https://github.com/Otach/cryptools.git
$ python setup.py install
```

## Usage
```
$ python
>>> from cryptools import *
```
There are the sample codes. <- TODO


## License
MIT
```
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

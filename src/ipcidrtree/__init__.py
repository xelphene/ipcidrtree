"""
ipcidrtree - A module which provides classes for representing IPv4
addresses and netmasks, particularly in tree structures organized by CIDR
hierarchy.

EXAMPLES:

	>>> import ipcidrtree
	>>> ipcidrtree.isValidAddress('1.2.3.4')
	True
	>>> ipcidrtree.isValidAddress('1.2')
	False
	>>> ipcidrtree.isValidRange('10.0.0.1-9')
	True
	>>> ipcidrtree.isValidRange('10.0.0.1-asdf')
	False
	>>> ipcidrtree.isValidNetwork('10.0.0.0/24')
	True
	>>> ipcidrtree.isValidNetwork('10.0.0.1/24')
	False
	>>> ipcidrtree.isValidNetwork('10.0.0.1/99')
	False
	>>> ipcidrtree.isValidNetwork('10.0.0.0/255.255.255.0')
	True
	>>> ipcidrtree.isValidSomething('10.0.0.0/255.255.255.0')
	True
	>>> ipcidrtree.isValidSomething('10.0.0.0/24')
	True
	>>> ipcidrtree.isValidSomething('10.0.0.0-10.0.0.9')
	True
	>>> ipcidrtree.isValidSomething('10.0.0.3')
	True

                                                       
TODO:
* make member data privte with _.
* write examples, doctest em.
* document any remaining methods

"""

__copyright__ = """
Copyright (c) 2016, Steve Benson
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
"""

import re
import types
import sys
import math

__version__='1.3.0'
__author__='Steve Benson'
__date__='2023-oct-30'

def plen2int(plen):
	"""Takes an integer in 0..32 (a subnet mask expressed in "slash"
	notation) and returns a 32 bit unsigned integer representing the netmask."""
	return (2**plen-1) * 2**(32-plen)

def _log2(n):
	"""Returns the log base 2 of an integer."""
	return math.log(n)/math.log(2)

def _bits32(i):
	"""Truncates an integer to 32 bits."""
	return i&4294967295

def parseIntQuads(*quads):
	
	'''given four integers that are the octets of an IP address, return the
	ip address as an integer.'''
	
	if len(quads)!=4:
		raise TypeError('parseQuads takes exactly 4 int arguments')
	
	# now, parse the address itself
	addr=0
	pow_of_two=[16777216,65536,256,1]
	for i in range(4):
		oc = quads[i]
		if oc > 255:
			# ParseError
			raise ValueError('Invalid IPv4 address - octet %d out of range' % (i+1))
		addr += oc * pow_of_two[i]
	return addr

def parseStrQuads(s):
	
	'''given a string of the form 'x.x.x.x', return it as an IP number integer'''
	
	parts = s.split('.')
	
	if len(parts)!=4:
		raise ValueError('too many dotted-separated parts in IP number %s' % repr(s))
	
	for p in parts:
		if not p.isdigit():
			raise ValueError('non-digit dotted-separated part in IP number %s' % repr(s))

	parts = [int(p) for p in parts]

	try:
		return parseIntQuads(*parts)
	except ValueError as ve:
		raise ValueError('invalid IP address %s: %s' % (repr(s), str(ve)))


valid_masks= [4294967295, 4294967294, 4294967292, 4294967288, 4294967280, 4294967264, 4294967232, 4294967168, 4294967040, 4294966784, 4294966272, 4294965248, 4294963200, 4294959104, 4294950912, 4294934528, 4294901760, 4294836224, 4294705152, 4294443008, 4293918720, 4292870144, 4290772992, 4286578688, 4278190080, 4261412864, 4227858432, 4160749568, 4026531840, 3758096384, 3221225472, 2147483648, 0]


def isIntValidNetmask(i):

	'''is the given integer a valid subnet mask?'''

	return i in valid_masks


class Parser:
	
	CACHE_MAX_LEN = 1000
	
	"""This is a string parser. It parses address/prefix strings into binary
	integer or object representations. This parse code is in a separate
	class since several classes in this module need to do this stuff. This
	also allows for easy addition of new formats to understand. This is a
	singleton class so we can re-use precompiled regexes everywhere."""
	
	class __impl:
		def __init__(self):
			self.exp_simple=re.compile('^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$')
			self.exp_prefix=re.compile('^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/([0-9]{1,2})$')
			self.exp_net_netmask=re.compile('^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$')
			#"""
			self._parse_o_cache = {}
		
		def flush_cache(self):
			if len(list(self._parse_o_cache.keys())) > Parser.CACHE_MAX_LEN:
				while len(list(self._parse_o_cache.keys())) > Parser.CACHE_MAX_LEN:
					del self._parse_o_cache[list(self._parse_o_cache.keys())[0]]
		
		def parse_o(self,s):
			"""Parse a string in and return a tuple of (Address,Netmask)
			objects. The Netmask item may be None if the string doesn't seem
			to contain a netmask."""
			if s in self._parse_o_cache:
				return self._parse_o_cache[s]
			
			self.flush_cache()
			
			(addr_i,mask_i) = self.parse_i(s)
			if mask_i is not None:
				rv = (Address(addr_i), Netmask(mask_i))
				self._parse_o_cache[s] = rv
				return rv
			else:
				rv = (Address(addr_i), None)
				self._parse_o_cache[s] = rv
				return rv

		def parse_i(self,s):
			
			"""Parse a string in and return a tuple of integers, (address,
			netmask).  The netmask int may be None if the string doesn't
			seem to contain a netmask."""

			mask=None

			mg_s = self.exp_simple.match(s)
			mg_p = self.exp_prefix.match(s)
			mg_m = self.exp_net_netmask.match(s)
			
			if mg_s: # this is a plain address
				mg=mg_s
			elif mg_p: # this is an addr with a mask len (x.x.x.x/y)
				mg=mg_p
				plen = int(mg.group(2))
				if plen < 0 or plen>32:
					# ParseError
					raise ValueError('Invalid value %d for prefix len (out of range)' % plen)
				# convert prefix len to a mask
				mask=(2**plen-1) * 2**(32-plen)
			elif mg_m: # addr with full mask (x.x.x.x/y.y.y.y)
				mg = mg_m
				mask = parseStrQuads(mg.group(2))
				if not isIntValidNetmask(mask):
					raise ValueError('Invalid netmask')
				
			else:
				raise ValueError("Unparseable IPv4 object: '%s'"%(str(s)))

			# now, parse the address itself
			addr = parseStrQuads(mg.group(1))

			return (addr,mask)
	
	# reference to the one instance of the parser
	__instance = None
	
	def __init__(self):
		if Parser.__instance is None:
			Parser.__instance = Parser.__impl()

		self.__dict__['_Parser__instance'] = Parser.__instance
	
	def __getattr__(self, attr):
		return getattr(self.__instance, attr)
            
	def __setattr__(self, attr, value):
		return setattr(self.__instance, attr, value)


class IPNumber:

	"""This class is basically just a 32 bit unsigned integer as used in
	IPv4 addresses."""

	def __init__(self,val):

		"""The address argument can be a string (which will be parsed to an
		integer via the Parser class), an integer (such that 0 <= i
		< 2**32), or another Address or subclass.""" 

		if type(val)==bytes or type(val)==str:
			(addr,mask) = Parser().parse_i(val)
			if mask is not None:
				raise ValueError('string argument "%s" to IPNumber constructor contains a netmask.' % val)
			#self._set_int(p.parse(val))
			self._set_int(addr)

		elif type(val)==int:
			self._set_int(val)
		
		#elif type(val)==types.InstanceType and issubclass(val.__class__,IPNumber):
		elif isinstance(val, IPNumber):
			self._ip_int=val._ip_int

		else:
			raise TypeError('Cannot convert from %s to IPNumber' % type(val))
	
	def _set_int(self,ipnum): 

		"""Set this Address object's value to a given binary integer address
		value."""

		if type(ipnum) not in [int, int]:
			raise TypeError('Invalid type for integer IPv4 number')
		if not (ipnum>=0 and ipnum<=2**32-1):
			raise ValueError('Invalid integer IPv4 number: %d (out of range)' % ipnum)
		self._ip_int = ipnum
		
	def __hash__(self): # TODO
		return hash(str(self))
		
	def __str__(self):
		oc1 = (self._ip_int&4278190080)/16777216
		oc2 = (self._ip_int&16711680)/65536
		oc3 = (self._ip_int&65280)/256
		oc4 = (self._ip_int&255)
		return '%d.%d.%d.%d' % (oc1,oc2,oc3,oc4)

	def __repr__(self):
		return "%s('%s')" % (self.__class__.__name__,str(self))
	
	def __int__(self):
		return self._ip_int

	def __eq__(self,other):
		try:
			return self._ip_int == IPNumber(other)._ip_int
		except ValueError as ve:
			return False

	def __add__(self,i):

		"""Simply add integer i to this Address's binary integer value and
		return a new Address that represents it. 10.0.0.1+1 =
		10.0.0.2.  10.0.0.255+1 = 10.0.1.0."""
		
		# convert other to an int if needed
		if type(i) not in [int, int]:
			raise TypeError("Cannot add type '%s' to IPNumber" % type(i))
			
		# check range
		if self._ip_int+i > 2**32-1:
			raise ValueError('Cannot add %d to %s: result out of range' % (i,self))

		return IPNumber(self._ip_int+i)

	def __sub__(self,other):
		"""Just the inverse of __add__."""
	
		# convert other to an int address if needed
		if type(other)==int:
			oi=other
		else:
			oi = IPNumber(other)._ip_int

		return self+(-oi) # rely on __add__

	def __lt__(self,other):
		return int(self) < int(other)
	
	def __le__(self,other):
		return int(self) <= int(other)
	
	def __ne__(self,other):
		return int(self) != int(other)
	
	def __gt__(self,other):
		return int(self) > int(other)
	
	def __ge__(self,other):
		return int(self) >= int(other)
		

class Netmask(IPNumber):
	"""This class represents an IPv4 network mask. It is mainly meant to
	be used as a primitive type used within the Prefix class."""
	
	_valid_masks= [4294967295, 4294967294, 4294967292, 4294967288, 4294967280, 4294967264, 4294967232, 4294967168, 4294967040, 4294966784, 4294966272, 4294965248, 4294963200, 4294959104, 4294950912, 4294934528, 4294901760, 4294836224, 4294705152, 4294443008, 4293918720, 4292870144, 4290772992, 4286578688, 4278190080, 4261412864, 4227858432, 4160749568, 4026531840, 3758096384, 3221225472, 2147483648, 0]

	sizes_to_prefix_lens = {
		1: 32,
		2: 31,
		4: 30,
		8: 29,
	}

	def __init__(self,val):
		if val.__class__ == self.__class__:
			IPNumber.__init__(self,val)
		else:
			if (type(val)==int or type(val)==int) and 0<=val<=32:
				val=plen2int(val)
			IPNumber.__init__(self,val)

	def _set_int(self,mask_i):
		if type(mask_i) not in [int, int]:
			raise TypeError('Invalid type for integer netmask')
		if mask_i not in Netmask._valid_masks:
			raise ValueError('Integer %d is not a valid netmask' % mask_i)
		self._ip_int=mask_i
		
	# TODO: make this faster... 
	# check for the common /32 by comparing to a constant
	def prefix_len(self):
		"""Returns this Netmask expressed in CIDR "slash" notation."""
		return 32-int(_log2( _bits32(~self._ip_int)+1) )

	def netsize(self):
		"""Returns the number of addresses that a network with this Netmask would have."""
		return 2**(32-self.prefix_len())
	
	@classmethod
	def by_netsize(cls, netsize):

		"""return a new Netmask for a network with netsize number of
		addresses in it. netsize must be a power of two and 0 <= netsize <=
		2**32."""
		
		if netsize<0 or netsize>2**32:
			raise ValueError('netsize is out of range')
		exp = math.log(netsize, 2)
		if exp!=int(exp):
			raise ValueError('netsize is not a power of two')
		plen = 32-int(exp)
		return cls(plen)

class Address(IPNumber):
	"""
	This class represents a simple IPv4 IP address. It is mainly meant to
	be used as a primitive type used within the Prefix class.
	"""
	pass
		

class Prefix:
	def __init__(self,address,netmask=None):
		self.netmask=None
		if type(address)==str:
			(self.addr, self.netmask) = Parser().parse_o(address)
			if self.netmask is None:
				# negligible
				self.netmask=Netmask(32)
		else:
			self.addr=Address(address)

		if netmask is not None:
			self.netmask=netmask
		elif netmask is None and self.netmask is None:
			self.netmask=Netmask(32)
		
		if int(self.addr) & _bits32(~int(self.netmask)) != 0: # .15
			if netmask:
				raise ValueError("network bits overflow prefix length in %s/%s" % (address,netmask))
			else:
				raise ValueError("network bits overflow prefix length in prefix '%s'" % address)

	def address(self):
		"""returns the Address of this Prefix. A Prefix is the combination of
		a suitable Address and Netmask."""
		return self.addr

	def addrs(self):
		"""Returns an Iterator over all addresses covered by this Prefix. Yields
		new Prefix objects with /32 netmasks."""
		return self.subnet( Netmask('255.255.255.255') )

	def network(self):
		"""Returns the network address within this Prefix. Return value is a
		Prefix with a /32 netmask."""
		return self[0]
	
	def broadcast(self):
		"""Returns the broadcast address within this Prefix. Return value is
		a Prefix with a /32 netmask."""
		return self[-1]

	def ishost(self):
		"""Returns True if this is a /32, False otherwise."""
		return self.netmask.prefix_len()==32

	def hosts(self):
		"""Returns an Iterator over all host addresses covered by this
		Prefix. Similar to addrs() minus network and broadcas addresses.
		Yields new Prefix objects with /32 netmasks."""
		net=self.network()
		bcast=self.broadcast()
		for a in self.addrs():
			if a not in [net,bcast]:
				yield a
	
	# make some or all of this prefix's network bits change to the network
	# bits in new_prefix
	def renumber(self,new_prefix):
		#if int(new_prefix) != int(new_ipnum) &int(self.netmask):
		#	raise ValueError("Can't renumber")
		if self.netmask.prefix_len() < new_prefix.netmask.prefix_len():
			raise ValueError("Can't renumber to a prefix with more bits (/%d) than self (/%d)" % (new_prefix.netmask.prefix_len(), self.netmask.prefix_len()) )
		
		keepmask = _bits32(~int(new_prefix.netmask))
		keepbits = int(self.addr) & keepmask
		self.addr._set_int(int(new_prefix.addr) | keepbits)
	
	def __eq__(self,other):
		if other==None:
			return False
			
		#if not type(other)==types.InstanceType:
		#if not isinstance(other):
		#	raise TypeError('Prefix.__eq__ requires Prefix or Address object, given value of type "%s" instead' % type(other))

		#if not (issubclass(other.__class__,Prefix) or issubclass(other.__class__,Address)):
		#	raise TypeError('Prefix.__eq__ requires Prefix or Address object, given object of class "%s" instead' % other.__class__.__name__)
		if not isinstance(other, (Prefix,Address)):
			raise TypeError('Prefix.__eq__ requires Prefix or Address object, given object of class "%s" instead' % other.__class__.__name__)
		
		if issubclass(other.__class__,Prefix):
			return self.addr==other.addr and self.netmask==other.netmask
		else: # its an Address
			return self.addr==other

	def __cmp__(self,other):
		"""Usually used to sort Prefixes. When used for sorting, this will cause
		Prefixes to be sorted by numeric order of their Addresses. Prefixes
		that contain one another will first be sorted by most specific-ness
		(ie, longest mask len) first and the Address numeric value second. If
		each Prefix has an equal mask len, then sort by Address's sort
		methods."""
		if self in other or other in self:
			if self.netmask.prefix_len() == other.netmask.prefix_len():
				if self.addr < other.addr:
					return -1
				elif self.addr > other.addr:
					return 1
				else:
					return 0
			elif self.netmask.prefix_len() > other.netmask.prefix_len():
				return -1
			else:
				return 1
		else:
			if self.addr < other.addr:
				return -1
			elif self.addr > other.addr:
				return 1
			else:
				return 0

	def __lt__(self,other):
		"""Usually used to sort Prefixes. When used for sorting, this will cause
		Prefixes to be sorted by numeric order of their Addresses. Prefixes
		that contain one another will first be sorted by most specific-ness
		(ie, longest mask len) first and the Address numeric value second. If
		each Prefix has an equal mask len, then sort by Address's sort
		methods."""
		if self in other or other in self:
			if self.netmask.prefix_len() == other.netmask.prefix_len():
				return self.addr < other.addr
			elif self.netmask.prefix_len() > other.netmask.prefix_len():
				return True
			else:
				return False
		else:
			return self.addr < other.addr
			
	
	def __str__(self):
		return '%s/%d' % (str(self.addr),self.netmask.prefix_len())

	def __repr__(self):
		return "%s('%s')" % (self.__class__.__name__, str(self))
	
	def __len__(self):
		return self.netmask.netsize()
	
	def __iter__(self):
		return self.addrs()

	# TODO: this is way too slow in the non-/32 cases
	def __hash__(self):
		if int(self.netmask) == 4294967295:
			return hash( int(self.addr) )
		else:
			return hash(str(self))

	def __contains__(self,other):
		from ipcidrtree.iprange import Range
		if issubclass(other.__class__, Range):
			return (
				other.first() >= self.network().address() and
				other.last() <= self.broadcast().address()
			)
			
		if other.__class__ != self.__class__:
			other=Prefix(other)
		
		if other.netmask.prefix_len() <= self.netmask.prefix_len():
			return False
		
		other_remasked = int(self.netmask) & int(other.addr)
		if other_remasked==int(self.addr):
			return True
		else:
			return False

	def contains(self,other):
		return other in self

	# is the integer index a valid index into us when used as a list?
	def _index_ok(self,index):
		if index<0:
			if abs(index)>len(self):
				return False
			return True
		else:
			if index>=len(self):
				return False
			return True

	def _int_slice(self,start,stop,step):
		rv=[]
		if start is None:
			start=0
		
		if stop is None:
			stop=len(self)
		elif stop==sys.maxsize:
			stop=len(self)
		
		if step is None:
			for i in range(start,stop):
				if self._index_ok(i):
					rv.append(self[i])
		else:
			for i in range(start,stop,step):
				if self._index_ok(i):
					rv.append(self[i])
		return rv
	
	def _other_slice(self,start,stop,step):
		try:
			start=Address(start)
			stop=Address(stop)
		except ValueError as ve:
			raise TypeError('Prefix slice indicies must be integers or a type convertible to Address')
		
		if step is None:
			step=1
		elif type(step) is not int:
			raise TypeError('slice step must be an integer or None')

		rv=[]
		for ai in range( int(start), int(stop), step):
			rv.append( Prefix(ai) )
		return rv
		
	def __getitem__(self,key): # implements prefix[i] and prefix[i:j]

		# handle plain old integer indexes
		if type(key)==int:
			if not self._index_ok(key):
				raise IndexError('Prefix index out of range')
			if key<0:
				return Prefix(int(self.addr)+len(self)+key)
			else:
				return Prefix(int(self.addr)+key)
		
		# handle slices
		if type(key)==slice:

			# if this is an ordinary integer slice...
			if (    (type(key.start)==int or key.start is None)
			    and (type(key.stop) ==int or key.stop  is None)
			    and (type(key.step) ==int or key.step  is None)):
			 
				return self._int_slice(key.start,key.stop,key.step)			 

			# some other type of slicing... try to convert them
			# to Addresses
			else:
				return self._other_slice(key.start,key.stop,key.step)

		else:
			raise TypeError('Prefix indicies must be integers or slices')

	def __add__(self,i):
		
		"""Add the integer i to the network portion of this prefix. Example:
		Prefix('10.0.0.0/24')+1 == Prefix('10.0.1.0/24')."""
	
		if type(i)!=int:
			raise TypeError('Cannot add Prefix and %s objects' % str(type(i)))
		shifted_i = i * self.netmask.netsize() #2**(32-self.prefix_len)

		# when adding two Addresses, a ValueError can be thrown. That means
		# the result of the addition would be a value out of range to be an
		# IP address. We basically catch & rethrow here because the
		# ValueError thrown by the Address addition contains the shifted_i
		# value, which will look strange to the user.
		try:
			return Prefix(self.addr + shifted_i, self.netmask)
		except ValueError:
			raise ValueError('Cannot %d to %s: result out of range' % (i,str(self)) )

	def __sub__(self,i):
	
		"""Subtract the integer i from the network portion of this prefix.
		Example: Prefix('10.0.0.0/24')-1 == Prefix('9.255.255.0/24')."""
	
		if type(i)!=int:
			raise TypeError('Cannot subtract Prefix and %s objects' % str(type(i)))
		return self+(-i)
		
	def subnet(self,subnet_mask):
	
		"""Return an iterator over all prefixes within this prefix that are
		of subnet_mask size. subnet_mask can be anything that is an
		acceptable argument to the Netmask class constructor. subnet_mask
		must describe a network smaller than this Prefix object."""
	
		subnet_mask=Netmask(subnet_mask)
		if subnet_mask.prefix_len() < self.netmask.prefix_len():
			raise ValueError('subnet size must be smaller')
		cur=Prefix(self.addr,subnet_mask)
		while cur in self or cur==self:
			yield cur
			cur+=1


class DuplicatePrefixError(Exception):
	def __init__(self,prefix):
		self.prefix=prefix
	def __str__(self):
		return 'duplicate prefix: '+str(self.prefix)

class PrefixNode(object):
	
	"""This class represents a node in a tree of IP Prefix objects. The tree
	is always arranged in a correct CIDR hierarchy (ie, 10.0.0.0/8 contains
	10.1.2.3/32). Every PrefixNode represents one Prefix and can contain
	zero or more PrefixNodes as children."""

	def __init__(self,prefix):

		"""Returns a new PrefoxNode. The 'prefix' argument can be anything suitable as the argument to Prefix.__init__()."""

		if type(prefix)==types.InstanceType and issubclass(prefix.__class__,Prefix):
			self.prefix=prefix
		elif type(prefix)==types.InstanceType and issubclass(prefix.__class__,Address):
			self.prefix = Prefix(prefix)
		elif type(prefix)==bytes:
			self.prefix=Prefix(prefix)
		else:
			raise TypeError('PrefixNode constructor requires Prefix or string argument - got a %s' % type(prefix))
		

		self.children=[]

		# contains references to the same stuff above, only indexed by
		# the child's Prefix
		self._children_hash={}
		
		# a subset of our list of children, only the ones that are possible
		# parents
		self._children_pospars=[]

	def _rrenumber(self,new_prefix):
		self.prefix.renumber(new_prefix)
		for c in self.children:
			c.rrenumber(new_prefix)
	
	def renumber(self,old_prefix,new_prefix):
		"""Renumber a child node with prefix old_prefix and its children to
		new_prefix.  This will raise DuplicatePrefixError and put the tree back
		the way it was prior to the renumber if duplicates are created as a
		result of renumbering."""
		if not self.prefix.contains(old_prefix):
			raise ValueError("this node (%s) doesn't contain old_prefix (%s)" % (str(self.prefix), str(old_prefix)) )
		if not self.prefix.contains(new_prefix):
			raise ValueError("this node (%s) doesn't contain new_prefix (%s)" % (str(self.prefix), str(new_prefix)) )
		
		if self.find(new_prefix):
			raise ValueError("new prefix already exists")
		branch = self.prune(old_prefix)
		if not branch:
			raise ValueError("old prefix not found")
		
		branch._rrenumber(new_prefix)
		try:
			self.add(branch)
		except DuplicatePrefixError as dpe:
			branch._rrenumber(old_prefix)
			self.add(branch)
			raise DuplicatePrefixError(dpe.prefix)
		
	def sort(self):
		"""Sorts this tree in-place. Uses Prefix's __cmp__() for sorting."""
		self.children.sort()
		for child in self.children:
			child.sort()

	def _add_child(self,child):
		self.children.append(child)
		self._children_hash[child.prefix]=child
		if child.prefix.netmask.prefix_len()<32:
			self._children_pospars.append(child)
	
	def _rm_child(self,child):
		self.children.remove(child)
		del(self._children_hash[child.prefix])
		if child in self._children_pospars:
			self._children_pospars.remove(child)

	# TODO: this method is slow as ass, see note in body
	def add(self,new_child):
		"""Add a new PrefixNode to this tree. This will automatically add
		the new child to the correct place in the tree (as long as it is
		below or at this node). Normally you'd call this on the root of a
		tree."""

		# host nodes can't have children
		if self.prefix.netmask.prefix_len()==32:
			return False
			
		if not issubclass(new_child.__class__, PrefixNode):
			new_child=PrefixNode(new_child)

		# if I don't contain it, False
		if not new_child.prefix in self.prefix:
			return False
		
		# judging by time analysis, the slowness is in one of the next two
		# loops... (runtime grows exponentially with number of children)
		
		# see if any of my children contain it
		#  if one of them does, 
		# see if any of our children would like it first
		# this is too slow...
		#for node in self.children:
		for node in self._children_pospars:
			if node.add(new_child):
				return True

		# next, see if it would like to adpot one of our children 
		# and be our child
		if self.parenting(new_child):
			raise DuplicatePrefixError(new_child.prefix)

		# TODO: any better way to optimize this?
		if new_child.prefix.netmask.prefix_len()<32:
			for cur_child in self.children:
				if new_child.add(cur_child):
				
					self._add_child(new_child)
					self._rm_child(cur_child)
					
					return True
	
		# no children took it, but I contain it... 
		# so it must be my direct decendant
		self._add_child(new_child)
		return True

	# TODO: this is WAY slow
	def parenting(self,new_child):
		"""Return true/false if we are parenting a PrefixNode with an equivalent
		Prefix to new_child."""
		if new_child.prefix in self._children_hash:
			return True
		return False
		
		for c in self.children:
			if c.prefix==new_child.prefix:
				return True
		return False

	def prune(self,key):
		"""Search for a PrefixNode that matches key (a Prefix), remove it
		from the tree and return it."""

		if not (type(key)==types.InstanceType and issubclass(key.__class__,Prefix)):
			key=Prefix(key)

		# if this is the case, then they're asking us to prune the
		# root of the tree... throw an exception?
		if self.prefix==key:
			#return self
			raise ValueError("can't prune root of tree")

		# asked for a prefix that isn't me and can't be 
		# any of my children
		if not key in self.prefix:
			return None
		
		for c in self.children:
			if c.prefix==key:
				self._rm_child(c)
				return c
			else:
				rv=c.prune(key)
				if rv is not None:
					return rv

		return None
	
	def dfi(self,depth=0):
		"""Performs depth-first iteration over the tree rooted at this
		PrefixNode. Yields (PrefixNode, depth) tuples. depth is an int
		representing how deep in the tree Prefix is. 0=the root."""
		yield (self,depth)
		for c in self.children:
			for (n,d) in c.dfi(depth+1):
				yield (n,d)

	def dfi_part(self,depth=0,filter=[]):
		"""Performs a partial depth first iteration (like dfi()). This will
		 only descend through prefixes in the list 'filter'. Yields
		 (PrefixNode, depth, in_filter) tuples. PrefixNode and depth have
		 the same meaning as in dfi(). in_filter is a boolean and will be
		 True if PrefixNode is in the passed filter list."""
		yield (self,depth, self.prefix in filter)
		if self.prefix in filter:
			for c in self.children:
				for (node,cdepth,infilter) in c.dfi_part(depth=depth+1, filter=filter):
					yield (node,cdepth,infilter)

	def find(self,key):
		"""Searches for the Prefix 'key' within the tree rooted at this
		PrefixNode. Returns an exactly matching PrefixNode or None."""
		if not (type(key)==types.InstanceType and issubclass(key.__class__,Prefix)):
			key=Prefix(key)

		if self.prefix==key:
			return self

		# asked for a prefix that isn't me and can't be 
		# any of my children
		if not key in self.prefix:
			return None
		
		for c in self.children:
			r=c.find(key)
			if r:
				return r
		
		return None

	def find_loose(self,key):
		"""Searches for the Prefix 'key' within the tree rooted at this
		PrefixNode. Returns the closest matching PrefixNode or None (if no
		PrefixNodes contain the search key)."""
		if not (type(key)==types.InstanceType and issubclass(key.__class__,Prefix)):
			key=Prefix(key)

		# exact match
		if self.prefix==key:
			return self

		# I don't even contain it
		if not key in self.prefix:
			return None
		
		for c in self.children:
			r=c.find_loose(key)
			if r:
				return r
		
		return self

	def __str__(self):
		return str(self.prefix)

	def __cmp__(self,other):
		"""Calls Prefix.__cmp__ on the Prefix objects that this PrefixNode
		and other represent."""
		if other==None:
			return 1
		return self.prefix.__cmp__(other.prefix)

	def dump(self):
		"""Used for debugging. Prints out the tree an human-friendly way."""
		for (node,depth) in self.dfi():
			#print '    '*depth,node.prefix
			print('    '*depth,str(node))

class PPrefixNode(PrefixNode): 

	"""a PrefixNode which maintains a (circular) reference to its parent. 
	This means the parent of any given node in a tree can be easily found,
	but a circular reference is created necessitating manual tree
	destruction via the unlink() call. The parent reference gets set when
	add() is called."""
	
	def __init__(self, prefix):
		super(PPrefixNode,self).__init__(prefix)
		self.parent=None
	
	def _add_child(self, child):
		child.parent=self
		PrefixNode._add_child(self,child)
	
	def unlink(self):
		"""destroy the parent circular references."""
		self.parent=None
		for (child,depth) in self.dfi():
			child.parent=None

#############################################################

def isValidRange(s):

	'''is the given string a valid range (i.e. 10.0.0.1-9 or
	10.0.0.1-10.9.9.9)'''

	from ipcidrtree.iprange import probableRange
	return probableRange(s)		

def isValidAddress(s):
	
	'''is the given string a valid IPv4 Address (in dotted quad form)'''

	try:
		Address(s)
		return True
	except ValueError:
		return False

def isValidNetwork(s):

	'''is the given string a valid IPv4 network (i.e. in the form
	10.0.0.0/24 or 10.0.0.0/255.255.255.0)'''
	
	try:
		Prefix(s)
		return True
	except ValueError:
		return False
	

def isValidSomething(s):

	'''is the given string a valid IP address, network or range?'''
	
	return (
		isValidAddress(s) or
		isValidRange(s) or
		isValidNetwork(s)
	)

def parse(s):
	from ipcidrtree.iprange import Range
	if isValidRange(s):
		return Range(s)
	elif isValidNetwork(s):
		return Prefix(s)
	elif isValidAddress(s):
		return Address(s)
	else:
		raise ValueError(s)

def probableRange(s):
	import ipcidrtree.iprange
	return ipcidrtree.iprange.probableRange(s)
	

from ipcidrtree import Address, Prefix
from ipcidrtree.iprange import Range

class IPSet:
	def __init__(self):
		self._items = set()
		self._prefixes = set()
		self._ranges = set()
		self._addresses = set()
		self._all_addresses = set()

	def items(self):
		'''return all Address/Range/Prefix objects that were specifically added to this set.'''
		return self._items

	def addresses(self):

		'''returns a set containing Address objects for *all* IP addresses
		in this IPSet no matter how they were added (i.e. part of a Range,
		Prefix, etc).'''

		return self._all_addresses
	
	def addressGroups(self, max=16):

		'''return a list of lists of Address objects. There will be
		Addresses for every IP address represented in this set no matter
		what it was a part of when added.'''
		
		all = []
		cur = []
		for a in self.addresses():
			cur.append(a)
			if len(cur)==max:
				all.append(cur)
				cur = []
		if len(cur)>0:
			all.append(cur)

		return all
	
	def add(self, o):
		if issubclass(o.__class__, Prefix):
			self.addPrefix(o)
		elif issubclass(o.__class__, Address):
			self.addAddress(o)
		elif issubclass(o.__class__, Range):
			self.addRange(o)
		else:
			raise TypeError(o)

	def __contains__(self, o):
		if type(o)==str:
			if not '/' in o:
				o = Address(o)
				return o in self
			else:
				o = Prefix(o)
				return o in self
		elif issubclass(o.__class__, Prefix):
			return self.containsPrefix(o)
		elif issubclass(o.__class__, Range):
			return self.containsRange(o)
		elif issubclass(o.__class__, Address):
			return Prefix(o) in self
		else:
			raise TypeError('unable to test for type %s in IPSet  object' % (o.__class__.__name__))

	def __len__(self):
		return len(self._all_addresses)

	###########################################
	
	def addPrefix(self, o):
		self._items.add(o)
		self._prefixes.add(o)
		for addr in o.addrs():
			self._all_addresses.add(addr.address())
	
	def addRange(self, o):
		self._items.add(o)
		self._ranges.add(o)
		for addr in o:
			self._all_addresses.add( addr)
	
	def addAddress(self, o):
		self._items.add(o)
		self._addresses.add(o)
		self._all_addresses.add(o)
	
	
	def containsPrefix(self, o):
		if not issubclass(o.__class__, Prefix):
			raise TypeError(o)
		if o in self._prefixes:
			return True
		for sprefix in self._prefixes:
			if o==sprefix or o in sprefix:
				return True
		for range in self._ranges:
			if o in range:
				return True
		for addr in self._addresses:
			if o == addr:
				return True
		return False
	
	def containsRange(self, o):
		if not issubclass(o.__class__, Range):
			raise TypeError(o)
		if o in self._ranges:
			return True
		for irange in self._ranges:
			if o==irange or o in irange:
				return True
		for iprefix in self._prefixes:
			if o in iprefix:
				return True
		return False
	
	def containsAddress(self, o):
		if not issubclass(o.__class__, Address):
			raise TypeError(o)
		return o in self._all_addresses
	

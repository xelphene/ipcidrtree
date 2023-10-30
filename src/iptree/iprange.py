
import re

from iptree import Address, Prefix

class Range:
	def __init__(self, a, b=None):

		'''can either take one string OR two Address objects (first and last
		in the range)'''

		if type(a)==str and b==None:
			r = parseRange(a)
			self._first = r[0]
			self._last = r[-1]
		elif issubclass(a.__class__, Address) and issubclass(b.__class__, Address):
			self._first = a
			self._last = b
		else:
			raise TypeError("%s constructor requires either a string or two Address objects" % self.__class__.__name__)

	#first = property( fget = lambda self: self._first )
	#last = property( fget = lambda self: self._last )

	def first(self):
		return self._first
	
	def last(self):
		return self._last

	def __len__(self):
		count=0
		for i in self:
			count += 1
		return count

	def __iter__(self):
		for a in expandRange(self._first, self._last):
			yield a
		
	def __contains__(self, o):
		if issubclass(o.__class__, Prefix):
			return (
				o.network().address() >= self._first and
				o.broadcast().address() <= self._last
			)
		elif issubclass(o.__class__, Address):
			return (
				o >= self._first and
				o <= self._last
			)
		elif issubclass(o.__class__, Range):
			return (
				o.first() >= self.first() and
				o.last() <= self.last()
			)
		else:
			return False

	def __eq__(self, o):
		if issubclass(o.__class__, self.__class__):
			return (
				self.first() == o.first() and
				self.last()  == o.last()
			)
		else:
			return False

	def __hash__(self):
		return hash( (self.first(), self.last()) )
		
	def __str__(self):
		return '%s-%s' % (
			self.first(),
			self.last()
		)
		
re_range_simple   = re.compile('^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) *- *([0-9]{1,3})$')
re_range_complete = re.compile('^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) *- *([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$')

def probableRange(s):
	
	'''does the given string look like a range?'''

	return (
		bool(re_range_simple.match(s)) or
		bool(re_range_complete.match(s))
	)

def parseRange(s):

	'''given a string of any valid sort of address range, return all
	addresses within.'''

	if re_range_simple.match(s):
		return parseRangeSimple(s)
	elif re_range_complete.match(s):
		return parseRangeComplete(s)
	else:
		raise ValueError('unparseable range')

def parseRangeComplete(s):

	'''given a string of an address range like "10.0.0.1-10.0.0.9", return
	all addresses in the range.'''

	mg = re_range_complete.match(s)
	if not mg:
		raise ValueError('unparseable range')
	start = Address(mg.group(1))
	end = Address(mg.group(2))

	return expandRange( start, end )

def parseRangeSimple(s):

	'''given a string of an address range like "10.0.0.1-9", return all
	addresses in the range.'''

	mg = re_range_simple.match(s)
	if not mg:
		raise ValueError('unparseable range')
	start_s = mg.group(1)
	end_s = '.'.join(start_s.split('.')[0:-1]) + '.' + mg.group(2)
	
	return expandRange( Address(start_s), Address(end_s) )

def expandRange(start, end):

	'''given a start and end address (strings or Address objects), return
	them and all addresses in between.'''

	start = Address(start)
	end = Address(end)
	r = []
	for i in range(int(start),int(end)):
		#p = Prefix(Address(i))
		p = Address(i)
		r.append(p)
	r.append(Address(end))
	
	return r

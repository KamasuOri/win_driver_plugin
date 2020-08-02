import idc 
import idaapi
import idautils
import sys
import ida_nalt

if sys.version_info[0] == 3:
    xrange = range

def find_pool_tags():
	""" Dirty hack around IDA's type information, find references to tag using functions then the comment marking the tag 
	then add the function caller/tag to output dictionary.
	"""
	
	funcs = [
		'ExAllocatePoolWithTag',
		'ExFreePoolWithTag',
		'ExAllocatePoolWithTagPriority'
	]

	tags = {}

	def imp_cb(ea, name, ord):
		if name in funcs:
			for xref in idautils.XrefsTo(ea):
				call_addr = xref.frm
				caller_name = idc.get_func_name(call_addr)
				prev = idc.prev_head(call_addr)
				for _ in range(10):
					if idc.get_cmt(prev,0) == 'Tag' and idc.get_operand_type(prev, 1) == 5:
						tag_raw = idc.get_operand_value(prev, 1)
						tag = ''
						for i in range(3, -1, -1):
							tag += chr((tag_raw >> 8 * i) & 0xFF)
						if tag in tags.keys():
							tags[tag].add(caller_name)
						else:
							tags[tag] = set([caller_name])
						break
					prev = idc.prev_head(prev)
		return True
	
	nimps = ida_nalt.get_import_module_qty()

	for i in xrange(0, nimps):
		name = ida_nalt.get_import_module_name(i)
		if not name:
			continue

		ida_nalt.enum_import_names(i, imp_cb)
	return tags 
	
def get_all_pooltags():
	""" Returns a string with a 'pooltags.txt' formatted string of 'pool tag' - 'driver' - 'functions which use it'.
	"""
	
	tags = find_pool_tags()
	out = ''
	file_name = ida_nalt.get_root_filename()
	for tag in tags.keys():
		desc = 'Called by: '
		desc += ', '.join(tags[tag])
		out += '{} - {} - {}\n'.format(tag, file_name, desc)
	return out 

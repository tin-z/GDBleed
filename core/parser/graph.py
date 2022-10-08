

class Node:
  
  def __init__(self, Id, val, decl, body):
    self.Id = Id
    self.val = val
    self.decl = decl
    self.body = body
    self.edge_in = {}
    self.edge_out = {}
    self.edge_out_fine = {}
    self.func_object = None


  def get_f_object(self):
    return self.func_object

  def set_f_object(self, func_object):
    self.func_object = func_object

  def add_in(self, node):
    self.edge_in.update({node.Id:node})

  def del_in(self, node):
    del self.edge_in[node.Id]

  def add_out(self, node):
    self.edge_out.update({node.Id:node})

  def del_out(self, node):
    del self.edge_out[node.Id]

  def mov_out(self, node):
    self.edge_out_fine.update(
      {node.Id : node}
    )
    self.del_out(node)

  def is_fine(self) :
    return self.edge_out == {}







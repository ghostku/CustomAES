def compare(our, js, name='VALUE'):
  print 'Comparing %s' % name
  if isinstance(js, str):
    result = (our == js)
  
  print 'OUR is: %s' % our
  print 'JS is %s' % js
  print 'They are %s' % ('equal' if result else 'non equal')
  return result
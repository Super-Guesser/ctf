def babymd5(m, n, x_head, y_head, x, y):
    if x.startswith(x_head) and y.startswith(y_head):
        for _ in range(m):
            xhash = md5(x.encode('utf-8')).hexdigest()
            x = xhash
        for _ in range(n):
            yhash = md5(y.encode('utf-8')).hexdigest()
            y = yhash
        if xhash == yhash:
            return True
    return False

# conditions : (m, n, x_head, y_head) = (179, 4, 'ByQ', 'dead')

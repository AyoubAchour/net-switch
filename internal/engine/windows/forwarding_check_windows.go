package winengine

func (r *Routes) ForwardingIndex() int { return int(r.healthIndex.Load()) }

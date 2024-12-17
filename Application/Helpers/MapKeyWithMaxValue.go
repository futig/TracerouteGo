package helpers

func GetKeyWithMaxValue(myMap map[string]int) string {
	var maxKey string
	var maxValue int

	for key, value := range myMap {
		if value > maxValue || maxKey == "" {
			maxKey = key
			maxValue = value
		}
	}
	
	return maxKey
}

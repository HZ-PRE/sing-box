package geosite

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGeositeWriteReadCompat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input map[string][]Item
	}{
		{
			"empty_map",
			map[string][]Item{},
		},
		{
			"single_code_empty_items",
			map[string][]Item{"test": {}},
		},
		{
			"single_code_single_item",
			map[string][]Item{"test": {{Type: RuleTypeDomain, Value: "a.com"}}},
		},
		{
			"single_code_multi_items",
			map[string][]Item{
				"test": {
					{Type: RuleTypeDomain, Value: "a.com"},
					{Type: RuleTypeDomainSuffix, Value: ".b.com"},
					{Type: RuleTypeDomainKeyword, Value: "keyword"},
					{Type: RuleTypeDomainRegex, Value: `^.*$`},
				},
			},
		},
		{
			"multi_code",
			map[string][]Item{
				"cn": {{Type: RuleTypeDomain, Value: "baidu.com"}, {Type: RuleTypeDomainSuffix, Value: ".cn"}},
				"us": {{Type: RuleTypeDomain, Value: "google.com"}},
				"jp": {{Type: RuleTypeDomainSuffix, Value: ".jp"}},
			},
		},
		{
			"utf8_values",
			map[string][]Item{
				"test": {
					{Type: RuleTypeDomain, Value: "测试.中国"},
					{Type: RuleTypeDomainSuffix, Value: ".テスト"},
				},
			},
		},
		{
			"large_items",
			generateLargeItems(1000),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Write using new implementation
			var buf bytes.Buffer
			err := Write(&buf, tc.input)
			require.NoError(t, err)

			// Read back and verify
			reader, codes, err := NewReader(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)

			// Verify all codes exist
			codeSet := make(map[string]bool)
			for _, code := range codes {
				codeSet[code] = true
			}
			for code := range tc.input {
				require.True(t, codeSet[code], "missing code: %s", code)
			}

			// Verify items match
			for code, expectedItems := range tc.input {
				items, err := reader.Read(code)
				require.NoError(t, err)
				require.Equal(t, expectedItems, items, "items mismatch for code: %s", code)
			}
		})
	}
}

func generateLargeItems(count int) map[string][]Item {
	items := make([]Item, count)
	for i := range count {
		items[i] = Item{
			Type:  ItemType(i % 4),
			Value: strings.Repeat("x", i%200) + ".com",
		}
	}
	return map[string][]Item{"large": items}
}

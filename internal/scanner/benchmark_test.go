package scanner

import (
	"context"
	"fmt"
	"testing"

	"github.com/greysquirr3l/wordfence-go/internal/intel"
)

// generatePHPContent creates test PHP content of specified size
func generatePHPContent(size int) []byte {
	base := `<?php
// Sample PHP file for benchmark testing
function example_function($param) {
    $data = array();
    for ($i = 0; $i < 100; $i++) {
        $data[] = "item_" . $i;
    }
    return $data;
}

class ExampleClass {
    private $property;
    
    public function __construct($value) {
        $this->property = $value;
    }
    
    public function getProperty() {
        return $this->property;
    }
}

$instance = new ExampleClass("test");
echo $instance->getProperty();
`
	content := make([]byte, 0, size)
	for len(content) < size {
		remaining := size - len(content)
		if remaining >= len(base) {
			content = append(content, base...)
		} else {
			content = append(content, base[:remaining]...)
		}
	}
	return content
}

// createBenchmarkSignatureSet creates a signature set for benchmarking
// (named differently to avoid conflict with matcher_test.go)
func createBenchmarkSignatureSet(numSigs, numCommonStrings int) *intel.SignatureSet {
	sigSet := intel.NewSignatureSet()

	// Create common strings
	for i := 0; i < numCommonStrings; i++ {
		cs := intel.NewCommonString(fmt.Sprintf("common_string_%d", i))
		cs.SignatureIDs = []int{i % numSigs}
		sigSet.CommonStrings = append(sigSet.CommonStrings, cs)
	}

	// Create signatures
	for i := 0; i < numSigs; i++ {
		commonStringIDs := []int{}
		if i < numCommonStrings {
			commonStringIDs = []int{i}
		}
		sig := intel.NewSignature(
			i,
			fmt.Sprintf(`example_function|ExampleClass|item_%d`, i%100),
			fmt.Sprintf("TestSignature_%d", i),
			"Benchmark test signature",
			commonStringIDs,
		)
		sigSet.Signatures[i] = sig
	}

	return sigSet
}

// BenchmarkMatcherSmallFile benchmarks matching against a 1KB file
func BenchmarkMatcherSmallFile(b *testing.B) {
	sigSet := createBenchmarkSignatureSet(100, 50)
	matcher := NewMatcher(sigSet)
	content := generatePHPContent(1024) // 1KB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := matcher.NewMatchContext()
		_ = ctx.Match(context.Background(), content)
		ctx.Release()
	}
}

// BenchmarkMatcherMediumFile benchmarks matching against a 100KB file
func BenchmarkMatcherMediumFile(b *testing.B) {
	sigSet := createBenchmarkSignatureSet(100, 50)
	matcher := NewMatcher(sigSet)
	content := generatePHPContent(100 * 1024) // 100KB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := matcher.NewMatchContext()
		_ = ctx.Match(context.Background(), content)
		ctx.Release()
	}
}

// BenchmarkMatcherLargeFile benchmarks matching against a 1MB file
func BenchmarkMatcherLargeFile(b *testing.B) {
	sigSet := createBenchmarkSignatureSet(100, 50)
	matcher := NewMatcher(sigSet)
	content := generatePHPContent(1024 * 1024) // 1MB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := matcher.NewMatchContext()
		_ = ctx.Match(context.Background(), content)
		ctx.Release()
	}
}

// BenchmarkMatcherManySignatures benchmarks with a large signature set
func BenchmarkMatcherManySignatures(b *testing.B) {
	sigSet := createBenchmarkSignatureSet(1000, 500)
	matcher := NewMatcher(sigSet)
	content := generatePHPContent(10 * 1024) // 10KB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := matcher.NewMatchContext()
		_ = ctx.Match(context.Background(), content)
		ctx.Release()
	}
}

// BenchmarkMatchContextPool benchmarks MatchContext pool efficiency
func BenchmarkMatchContextPool(b *testing.B) {
	sigSet := createBenchmarkSignatureSet(100, 50)
	matcher := NewMatcher(sigSet)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := matcher.NewMatchContext()
		ctx.Release()
	}
}

// BenchmarkAhoCorasickPrefilter benchmarks the Aho-Corasick pre-filtering
func BenchmarkAhoCorasickPrefilter(b *testing.B) {
	// Create a signature set with many common strings to stress test AC
	sigSet := createBenchmarkSignatureSet(500, 200)
	matcher := NewMatcher(sigSet)
	content := generatePHPContent(50 * 1024) // 50KB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ctx := matcher.NewMatchContext()
		_ = ctx.Match(context.Background(), content)
		ctx.Release()
	}
}

// BenchmarkRegexCompile benchmarks regex compilation with multi-layer engine
func BenchmarkRegexCompile(b *testing.B) {
	patterns := []string{
		`\$\w+[\x00-\x1f\s]*=[\x00-\x1f\s]*['"][\w\/+=]{100,}['"]`,
		`base64_decode\s*\(`,
		`eval\s*\(\s*\$`,
		`preg_replace\s*\(\s*['"]/[^/]+/e`,
		`system\s*\(\s*\$`,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, p := range patterns {
			_, _ = CompileRegex(p, DefaultMatchTimeout)
		}
	}
}

// BenchmarkBufferPoolGetPut benchmarks buffer pool operations
func BenchmarkBufferPoolGetPut(b *testing.B) {
	pool := NewBufferPool(64 * 1024) // 64KB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := pool.Get()
		pool.Put(buf)
	}
}

// BenchmarkBufferPoolParallel benchmarks buffer pool under contention
func BenchmarkBufferPoolParallel(b *testing.B) {
	pool := NewBufferPool(64 * 1024) // 64KB

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := pool.Get()
			pool.Put(buf)
		}
	})
}

// BenchmarkFilterMatching benchmarks filter pattern evaluation
func BenchmarkFilterMatching(b *testing.B) {
	filter := NewFileFilter()
	filter.Allow(FilterPHP)
	filter.Allow(FilterJS)
	filter.Allow(FilterHTML)
	filter.Deny(FilterImages)

	testPaths := []string{
		"/var/www/html/index.php",
		"/var/www/html/wp-content/plugins/test.php",
		"/var/www/html/assets/script.js",
		"/var/www/html/assets/style.min.js",
		"/var/www/html/images/photo.jpg",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, path := range testPaths {
			_ = filter.Filter(path)
		}
	}
}

//go:build darwin && cgo && keyvault_abi_tests

package main

/*
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#ifndef KEYVAULT_NMC_INIT_CALLBACKS_V1
#define KEYVAULT_NMC_INIT_CALLBACKS_V1
typedef struct kv_nmc_init_callbacks_v1 {
 void *context;
 int (*require_absent)(void *);
 int (*create_initialized_anchor)(void *, const unsigned char *, size_t);
 int (*load_protected)(void *, unsigned char *, size_t, size_t *);
} kv_nmc_init_callbacks_v1;
#endif
// Explicit-test-tag-only fixture. No product private getter or mock provider.
typedef struct {unsigned char value[32768];size_t size;int fault,absences,creates,loads;} init_fixture_state;
static int init_fixture_absent(void *p) {
 init_fixture_state *s=(init_fixture_state *)p;s->absences++;
 if(s->size || (s->fault==1 && s->absences==1) || (s->fault==7 && s->absences==2)) return -1;
 return 0;
}
static int init_fixture_create(void *p,const unsigned char *b,size_t n) {
 init_fixture_state *s=(init_fixture_state *)p;s->creates++;
 if(s->size || !n || n>sizeof(s->value) || s->fault==2) return -1;
 memcpy(s->value,b,n);s->size=n;
 return s->fault==3 ? -1 : 0;
}
static int init_fixture_load(void *p,unsigned char *b,size_t cap,size_t *w) {
 init_fixture_state *s=(init_fixture_state *)p;s->loads++;
 if(!w || !s->size) return -1;
 *w=s->fault==5 ? 32769 : s->size;
 if(!b && cap==0) return 0;
 if(cap<s->size || !b) return -1;
 memcpy(b,s->value,s->size);
 if(s->fault==4) b[s->size-1]^=1;
 if(s->fault==6) *w=s->size-1;
 return 0;
}
static kv_nmc_init_callbacks_v1 init_fixture_callbacks(init_fixture_state *s) {
 kv_nmc_init_callbacks_v1 c={s,init_fixture_absent,init_fixture_create,init_fixture_load};
 if(s->fault==101)c.require_absent=NULL;
 if(s->fault==102)c.create_initialized_anchor=NULL;
 if(s->fault==103)c.load_protected=NULL;
 return c;
}
static init_fixture_state *init_fixture_new(int fault) {init_fixture_state *s=calloc(1,sizeof(init_fixture_state));if(s)s->fault=fault;return s;}
static void init_fixture_free(init_fixture_state *s){volatile unsigned char *p=(volatile unsigned char*)s;for(size_t n=0;n<sizeof(*s);n++)p[n]=0;free(s);}
*/
import "C"

import "unsafe"

type initializationCFixture struct{ state *C.init_fixture_state }

func newInitializationCFixture(fault int) *initializationCFixture {
	p := C.init_fixture_new(C.int(fault))
	if p == nil {
		panic("fixture allocation failed")
	}
	return &initializationCFixture{p}
}
func (f *initializationCFixture) close() {
	if f.state != nil {
		C.init_fixture_free(f.state)
		f.state = nil
	}
}
func (f *initializationCFixture) stats() (int, int, int, int) {
	s := f.state
	return int(s.absences), int(s.creates), int(s.loads), int(s.size)
}
func initializationFixtureOpen(pin, config []byte) (uint64, int32) {
	h := C.uint64_t(999)
	code := kv_nmc_init_open_v1(rootFixturePointer(pin), C.size_t(len(pin)), rootFixturePointer(config), C.size_t(len(config)), &h)
	return uint64(h), int32(code)
}
func initializationFixtureComplete(h uint64, material []byte, f *initializationCFixture) int32 {
	if f == nil {
		return int32(kv_nmc_init_complete_v1(C.uint64_t(h), rootFixturePointer(material), C.size_t(len(material)), nil))
	}
	c := C.init_fixture_callbacks(f.state)
	return int32(kv_nmc_init_complete_v1(C.uint64_t(h), (*C.uchar)(unsafe.Pointer(unsafe.SliceData(material))), C.size_t(len(material)), &c))
}
func initializationFixtureClose(h uint64) int32 { return int32(kv_nmc_init_close_v1(C.uint64_t(h))) }

func initializationFixtureCheckAbsent(h uint64) int32 {
	return int32(kv_nmc_init_check_absent_v1(C.uint64_t(h)))
}

#include <stdint.h>
#ifdef _WIN32
  #define VXE_API __declspec(dllexport)
#else
  #define VXE_API
#endif

// Lifecycle
VXE_API void vxe_main();                // The OS Mask calls this after binding
VXE_API void vxe_exit();                // Terminate
VXE_API void vxe_panic(uint64_t code);  // Emergency stop
VXE_API void vxe_launcher(uint64_t vxe_entry_adress);

// Memory
VXE_API uint64_t  vxe_alloc(uint64_t size);  // Returns address
VXE_API void vxe_free(uint64_t ptr);

// I/O
VXE_API uint64_t  vxe_write(uint64_t handle, uint64_t buffer, uint64_t len); // Returns bytes written
VXE_API uint64_t  vxe_read(uint64_t handle, uint64_t buffer, uint64_t len);  // Returns bytes read
VXE_API uint64_t  vxe_get_args();                             // Get command line

typedef struct VXE_Context {
  uint64_t (*vxe_alloc)(uint64_t size);
  void (*vxe_free)(uint64_t ptr);
  uint64_t (*vxe_write)(uint64_t handle, uint64_t buffer, uint64_t len);
  uint64_t (*vxe_read)(uint64_t handle, uint64_t buffer, uint64_t len);
  uint64_t (*vxe_get_args)();
} VXE_Context;

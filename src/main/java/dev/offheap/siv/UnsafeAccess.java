package dev.offheap.siv;

import java.lang.reflect.Field;
import sun.misc.Unsafe;

/** Single entry point for the JDK 8 {@code sun.misc.Unsafe} the arena and the cipher need. */
final class UnsafeAccess {

    static final Unsafe U;
    static final long BYTE_BASE;

    static {
        try {
            Field f = Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            U = (Unsafe) f.get(null);
            BYTE_BASE = Unsafe.ARRAY_BYTE_BASE_OFFSET;
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private UnsafeAccess() {
    }
}

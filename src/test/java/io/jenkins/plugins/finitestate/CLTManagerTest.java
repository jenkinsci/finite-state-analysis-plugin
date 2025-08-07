package io.jenkins.plugins.finitestate;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Test class for CLTManager utility.
 */
public class CLTManagerTest {

    @Test
    public void testCLTManagerClassExists() {
        // This test verifies that the CLTManager class can be loaded
        assertNotNull("CLTManager class should exist", CLTManager.class);
    }

    @Test
    public void testCLTManagerIsUtilityClass() {
        // This test verifies that CLTManager is designed as a utility class
        // by checking that it has a private constructor
        try {
            CLTManager.class.getDeclaredConstructor();
            // If we get here, the constructor exists but we need to check if it's private
            assertTrue(
                    "CLTManager constructor should be private",
                    CLTManager.class.getDeclaredConstructor().getModifiers() == java.lang.reflect.Modifier.PRIVATE);
        } catch (NoSuchMethodException e) {
            fail("CLTManager should have a private constructor");
        }
    }
}

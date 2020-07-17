package edu.cnm.deepdive;

import java.security.SecureRandom;
import java.util.Random;

public class PasswordGenerator {

  private static final String UPPER_CASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static final String LOWER_CASE = "abcdefghijklmnopqrstuvwxyz";
  private static final String DIGITS = "0123456789";
  private static final String PUNCTUATION = "~`!@#$%&*()-_+={}[]\\:;,./?";  //leave out some characters because they have special meaning in command lines
  private static final String AMBIGUOUS = "[O0l1]";

  private final Random rng;
  private final char[] pool;
  private final boolean upperCaseRequired;
  private final boolean lowerCaseRequired;
  private final boolean digitsRequired;
  private final boolean punctuationRequired;
  private final boolean ambiguousAllowed;

  private PasswordGenerator(Random rng, char[] pool, boolean upperCaseRequired,
      boolean lowerCaseRequired, boolean digitsRequired, boolean punctuationRequired,
      boolean ambiguousAllowed) {
    this.rng = rng;
    this.pool = pool;
    this.upperCaseRequired = upperCaseRequired;
    this.lowerCaseRequired = lowerCaseRequired;
    this.digitsRequired = digitsRequired;
    this.punctuationRequired = punctuationRequired;
    this.ambiguousAllowed = ambiguousAllowed;
  }

  public String generate(int length) throws IllegalArgumentException {

    StringBuilder builder = new StringBuilder(length);

    if (upperCaseRequired) {
      builder.append(selectRestricted(UPPER_CASE));
    }
    if (lowerCaseRequired) {
      builder.append(selectRestricted(LOWER_CASE));
    }
    if (digitsRequired) {
      builder.append(selectRestricted(DIGITS));
    }
    if (punctuationRequired) {
      builder.append(PUNCTUATION.charAt(rng.nextInt(PUNCTUATION.length())));
    }
    if (length < builder.length()) {
      throw new IllegalArgumentException("Specified length is insufficient for password requirements");
    }
    for (int i = builder.length(); i <length; i++) {
      builder.append(pool[rng.nextInt(pool.length)]);
    }
    char[] chars = builder.toString().toCharArray();
    for (int i = chars.length -1; i > 0; i--) {  //counting down this is..from end of the array
      int position = rng.nextInt(i + 1); //select position i to swap
      if (position != i) {
        char temp  = chars[i];
        chars[i] = chars[position];
        chars[position] = temp;  //temp is a temporary position for swapping process.
      }
    }
    return new String(chars);  //new string that contains that characters
    //created an array and allocated space. put upper, lower, digit in a builder; if builder is shorter
    // then asked trow Except; if no then add as many rng argument, lets shuffle and return the new string.
  }

  private String selectRestricted(String pool) {
    String selected;
    do {
      int position = rng.nextInt(pool.length());
      selected = pool.substring(position, position + 1);
    } while (!ambiguousAllowed && selected.matches(AMBIGUOUS));
    return selected;
  }


  public static class Builder {       //don't have in builder getters, we have the methods to set values; implement the fluent style; where return the builder again

    private Random rng;
    private boolean upperCaseAllowed = true;
    private boolean lowerCaseAllowed = true;
    private boolean digitsAllowed = true;
    private boolean punctuationAllowed = true;
    private boolean upperCaseRequired;
    private boolean lowerCaseRequired;
    private boolean digitsRequired;
    private boolean punctuationRequired;
    private boolean ambiguousAllowed;

    public Builder allowUpperCase() {
      return allowUpperCase(true);
    }

    public Builder allowUpperCase(boolean allowed)  {
      upperCaseAllowed = allowed;
      return this;
    }

    public Builder allowLowerCase() {
      return allowLowerCase(true);
    }

    public Builder allowLowerCase(boolean allowed)  {
      lowerCaseAllowed = allowed;
      return this;
    }

    public Builder allowDigits() {
      return allowDigits(true);
    }

    public Builder allowDigits(boolean allowed)  {
      digitsAllowed = allowed;
      return this;
    }

    public Builder allowPunctuation()  {
      return allowPunctuation(true);
    }

    public Builder allowPunctuation(boolean allowed)  {
      punctuationAllowed = allowed;
      return this;
    }

    public Builder requireUpperCase() {
      return requireUpperCase(true);
    }

    public Builder requireUpperCase(boolean required) {
      upperCaseRequired = required;
      return this; //this = return builder object
    }

    public Builder requireLowerCase()  {
      return requireUpperCase(true);
    }

    public Builder requireLowerCase(boolean required) {
      lowerCaseRequired = required;
      return this; //this = return builder object
    }

    public Builder requireDigits()  {
      return requireDigits(true);
    }

    public Builder requireDigits(boolean required) {
      digitsRequired = required;
      return this; //this = return builder object
    }

    public Builder requirePunctuation()  {
      return requirePunctuation(true);
    }

    public Builder requirePunctuation(boolean required) {
      punctuationRequired = required;
      return this; //this = return builder object
    }

    public Builder allowAmbiguous()  {
      return allowAmbiguous(true);
    }

    public Builder allowAmbiguous(boolean allowed)  {
      ambiguousAllowed = allowed;
      return this;
    }

    public Builder useRng(Random rng) {
      this.rng = rng;
      return this;
    }

    public PasswordGenerator build() throws IllegalStateException {         //builder will return passwordGenerator
      if (upperCaseRequired && !upperCaseAllowed) {
        throw new IllegalStateException("Upper-case cannot be both required and not allowed.");
      } else if (lowerCaseRequired && !lowerCaseAllowed) {
        throw new IllegalStateException("Lower-case cannot be both required and not allowed.");
      } else if (digitsRequired && !digitsAllowed) {
        throw new IllegalStateException("Digits cannot be both required and not allowed.");
      } else if (punctuationRequired && !punctuationAllowed) {
        throw new IllegalStateException("Punctuation cannot be both required and not allowed.");
      }
      StringBuilder pool = new StringBuilder();
      if (upperCaseAllowed) {      //putting case into a pool to be used.
        pool.append(UPPER_CASE);
      }
      if (lowerCaseAllowed) {
        pool.append(LOWER_CASE);
      }
      if (digitsAllowed) {
        pool.append(DIGITS);
      }
      if (punctuationAllowed) {
        pool.append(PUNCTUATION);
      }
      String generatorPool =
          ambiguousAllowed ? pool.toString() : pool.toString().replaceAll(AMBIGUOUS, ""); //pool is a StringBuilder // if ambiguous is allowed take a String builder and generate the string if not take ambiguous and replace with wmpty string
      return new PasswordGenerator(
          (rng != null) ? rng : new SecureRandom(),
          generatorPool.toCharArray(),
          upperCaseRequired,
          lowerCaseRequired,
          digitsRequired,
          punctuationRequired,
          ambiguousAllowed
      );
    }


  }
}

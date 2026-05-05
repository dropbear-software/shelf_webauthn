final class VerificationResult {
  final bool success;
  final int updatedSignCount;

  const VerificationResult({
    required this.success,
    required this.updatedSignCount,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is VerificationResult &&
          runtimeType == other.runtimeType &&
          success == other.success &&
          updatedSignCount == other.updatedSignCount;

  @override
  int get hashCode => success.hashCode ^ updatedSignCount.hashCode;
}

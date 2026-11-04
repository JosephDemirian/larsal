// Design parity (Verify): reads the text drawn in app snapshots with on-device
// text recognition (Vision), for strings that are drawn but kept out of the
// accessibility tree (decorative letter tiles, the window behind a modal
// menu). Writes target/parity/ocr/<theme>/<frame-id>.json: [{text, box}]
// with boxes in points (the PNGs are 2x). No window, no network.
// Usage: swift design/parity/tools/ocr.swift app-shots/light/*.png
import Foundation
import Vision

for path in CommandLine.arguments.dropFirst() {
    let url = URL(fileURLWithPath: path)
    guard let source = CGImageSourceCreateWithURL(url as CFURL, nil),
        let image = CGImageSourceCreateImageAtIndex(source, 0, nil)
    else { continue }
    let width = Double(image.width) / 2, height = Double(image.height) / 2
    let request = VNRecognizeTextRequest()
    request.recognitionLevel = .accurate
    request.usesLanguageCorrection = false
    request.recognitionLanguages = ["en-US"]
    try VNImageRequestHandler(cgImage: image).perform([request])
    var out: [[String: Any]] = []
    for result in request.results ?? [] {
        guard let best = result.topCandidates(1).first else { continue }
        let b = result.boundingBox
        let edges: [Double] = [b.minX * width, (1 - b.maxY) * height, b.width * width, b.height * height]
        let box: [Double] = edges.map { ($0 * 2).rounded() / 2 }
        out.append(["text": best.string, "box": box])
    }
    let data = try JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted])
    let folder = URL(fileURLWithPath: "target/parity/ocr").appending(path: url.deletingLastPathComponent().lastPathComponent)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    try data.write(to: folder.appending(path: url.deletingPathExtension().lastPathComponent + ".json"))
    print(path, out.count)
}

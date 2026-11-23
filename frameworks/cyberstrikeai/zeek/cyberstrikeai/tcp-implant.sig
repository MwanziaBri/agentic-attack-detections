# The CyberStrikeAI TCP implant sends the four bytes CSB1 in a segment of their own before its first frame.
signature cyberstrikeai-tcp-implant-magic {
  ip-proto == tcp
  payload-size == 4
  payload /^CSB1/
  tcp-state originator, established
  event "CyberStrikeAI TCP implant magic"
}

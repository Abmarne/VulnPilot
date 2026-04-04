from google import genai
import traceback

try:
    c = genai.Client(api_key='AIzaSyC03RYSVQnurGHXX5ZxTxmucTB7p4e-sCw')
    r = c.models.generate_content(model='gemini-2.0-flash', contents='Say OK in one word')
    print('SUCCESS:', r.text)
except Exception as e:
    print("FULL ERROR:")
    traceback.print_exc()
